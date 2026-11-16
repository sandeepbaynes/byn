package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// `byn unsecure NAME...` and `byn secure NAME...`.
//
// An unsecure value is stored unsealed: `byn get` returns it with no password,
// locked or not, and `byn exec` injects it without a trusted .byn. It is for
// the things a project keeps beside its secrets that are not secrets — a port,
// a region, a log level — so that reading them stops costing an approval.
//
// The two commands are one decision seen from two sides, and they are gated
// very differently. Making a value unsecure publishes something stored, to
// everything on the machine that can run byn, for good: it always takes the
// master password, and a session will not do. Making one secure takes access
// away, so anything that could already change the value may do it.

// runSecureSet is both commands; secure says which.
func runSecureSet(args []string, scope cliScope, secure bool) int {
	verb := "unsecure"
	if secure {
		verb = "secure"
	}
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dryRun := fs.Bool("dry-run", false, "show which values would change, and change nothing")
	jsonOut := fs.Bool("json", false, "emit {changed,unchanged} JSON instead of prose")
	pwStdin := fs.Bool("password-stdin", false, "read the master password from stdin for non-interactive authorization")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: byn %s NAME|GLOB [NAME|GLOB...]\n", verb)
		return exitErr
	}
	for _, p := range fs.Args() {
		if _, err := path.Match(p, ""); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid pattern %q: %v\n", p, err)
			return exitErr
		}
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	client := newClient(dir, scope.Vault)

	var listed ipc.ListResp
	if rc := handleCallError(client.Call(ipc.OpList, ipc.ListReq{Scope: scope.ToIPC()}, &listed)); rc != exitOK {
		return rc
	}
	plan, perr := planSecureSet(fs.Args(), listed.Secrets, secure)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
		return exitErr
	}
	for _, n := range plan.inherited {
		fmt.Fprintf(os.Stderr, "%s %s is inherited from the default env, so it is changed there: byn --env default %s %s\n",
			yellow("skipped:"), n, verb, n)
	}

	if *dryRun || len(plan.change) == 0 {
		return reportSecureSet(verb, scope, plan.change, plan.already, *jsonOut, true)
	}

	req := ipc.SecureSetReq{Scope: scope.ToIPC(), Names: plan.change, Secure: secure}
	var resp ipc.SecureSetResp
	var lastErr error
	call := func(pw []byte) error {
		req.Password = pw
		resp = ipc.SecureSetResp{}
		lastErr = client.Call(ipc.OpSecureSet, req, &resp)
		return lastErr
	}

	var rc int
	if secure {
		rc = mutateWithAuthRetry(*pwStdin, *jsonOut, true, nil, call)
	} else {
		rc = unsecureWithPassword(plan.change, scope, *pwStdin, *jsonOut, call)
	}
	if rc != exitOK {
		if *jsonOut {
			emitCallErrorJSON(os.Stdout, map[string]any{"names": plan.change}, lastErr, rc)
		}
		return rc
	}
	return reportSecureSet(verb, scope, resp.Changed, append(resp.Unchanged, plan.already...), *jsonOut, false)
}

// unsecureWithPassword asks for the master password BEFORE the first call.
//
// The other gated commands try without one and prompt only if refused, which is
// right for them: a session usually answers. This is never answered by a
// session, so trying first would only write a denial into the audit log on
// every honest use — and the prompt is the moment to say, in plain words, what
// is about to become public.
func unsecureWithPassword(names []string, scope cliScope, pwStdin, jsonMode bool, call func([]byte) error) int {
	if !pwStdin && (jsonMode || !canPrompt()) {
		// Nobody to ask. Let the daemon refuse, so the caller gets the same
		// error, exit code and wording as any other gated command.
		return handleCallError(call(nil))
	}
	lead := yellow("Making unsecure in "+scope.String()+": ") + strings.Join(names, ", ")
	if !pwStdin {
		if risky := secretLookingNames(names); len(risky) > 0 {
			lead += "\n" + boldYellow("Check these — the name suggests a secret: ") + strings.Join(risky, ", ")
		}
		lead += "\n" + dim("They become readable with no password, by anything on this machine that can run byn.")
	}
	pw, wipe, err := authorizingPasswordWithLeadIn(pwStdin, lead)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	defer wipe()
	return handleCallError(call(pw))
}

// securePlan is what a list of names and globs resolves to in one scope.
type securePlan struct {
	change    []string // in the scope and not yet in the requested state
	already   []string // in the scope and already there
	inherited []string // matched by a glob but living in the default env
}

// planSecureSet resolves the arguments against the scope's listing.
//
// An exact name is passed through even when the listing does not have it, or
// has it only by inheritance: the daemon's refusal for that name is more
// precise than anything said here, and it stops the whole request, which is
// what naming something that cannot be changed should do. A glob is different —
// it means "whatever matches", so an inherited match is skipped and reported,
// and a glob matching nothing at all is an error rather than a silent no-op.
func planSecureSet(args []string, secrets []ipc.SecretMeta, secure bool) (securePlan, error) {
	byName := make(map[string]ipc.SecretMeta, len(secrets))
	for _, s := range secrets {
		byName[s.Name] = s
	}
	var plan securePlan
	seen := map[string]struct{}{}
	add := func(name string, explicit bool) {
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		s, known := byName[name]
		switch {
		case !known:
			plan.change = append(plan.change, name) // explicit only; the daemon says "not found"
		case s.Source != "scope" && !explicit:
			plan.inherited = append(plan.inherited, name)
		case s.Source == "scope" && s.Unsecure != secure:
			plan.already = append(plan.already, name)
		default:
			plan.change = append(plan.change, name)
		}
	}
	for _, arg := range args {
		if !strings.ContainsAny(arg, "*?[") {
			add(arg, true)
			continue
		}
		matched := false
		for _, s := range secrets {
			if ok, _ := path.Match(arg, s.Name); ok {
				matched = true
				add(s.Name, false)
			}
		}
		if !matched {
			return securePlan{}, fmt.Errorf("%q matches nothing in this scope", arg)
		}
	}
	sort.Strings(plan.change)
	sort.Strings(plan.already)
	sort.Strings(plan.inherited)
	return plan, nil
}

// secretLookingNames picks out names that read like credentials. It is a
// prompt for a second look and nothing more: byn cannot know what a value is,
// and plenty of harmless settings have KEY in their name.
func secretLookingNames(names []string) []string {
	var out []string
	for _, n := range names {
		u := strings.ToUpper(n)
		for _, word := range []string{"SECRET", "PASSWORD", "PASSWD", "TOKEN", "PRIVATE", "CREDENTIAL", "API_KEY", "APIKEY", "ACCESS_KEY", "_KEY"} {
			if strings.Contains(u, word) {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

func reportSecureSet(verb string, scope cliScope, changed, unchanged []string, jsonOut, dryRun bool) int {
	sort.Strings(changed)
	sort.Strings(unchanged)
	if jsonOut {
		obj := map[string]any{
			"scope":     scope.String(),
			"secure":    verb == "secure",
			"changed":   nonNil(changed),
			"unchanged": nonNil(unchanged),
		}
		if dryRun {
			obj["dry_run"] = true
		}
		out, _ := json.Marshal(obj)
		fmt.Println(string(out))
		return exitOK
	}
	state := "unsecure"
	if verb == "secure" {
		state = "sealed"
	}
	for _, n := range unchanged {
		fmt.Fprintf(os.Stderr, "%s %s is already %s\n", dim("unchanged:"), n, state)
	}
	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "(nothing to change)")
		return exitOK
	}
	if dryRun {
		fmt.Fprintf(os.Stderr, "Would make %s in %s: %s\n", state, scope, strings.Join(changed, ", "))
		return exitOK
	}
	if verb == "secure" {
		fmt.Fprintf(os.Stderr, "Sealed in %s: %s\n", scope, strings.Join(changed, ", "))
		// Sealing protects the value from here on. It does not un-read it.
		fmt.Fprintln(os.Stderr, dim("These were readable with no password until now. If one is a real secret, rotate it."))
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "%s in %s: %s\n", yellow("Now unsecure"), scope, strings.Join(changed, ", "))
	fmt.Fprintln(os.Stderr, dim("Readable with no password by anything that can run byn. Undo with: byn secure NAME"))
	return exitOK
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
