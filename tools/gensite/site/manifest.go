package site

// Manifest is the curated set of pages the site publishes, in order. It is the
// ONE place hand-curation lives: nav active state, breadcrumbs, the prev/next
// pager chain, GitHub source paths, and which markdown file backs each output.
//
// Everything *within* a page — title, description, the left sidebar's section
// links, and the on-this-page TOC — is derived from the doc's own markdown, so
// editing a doc's headings reshapes its nav with no manifest change. That
// content-derivation is the maintenance win this generator exists to deliver.
//
// Why a manifest rather than "render every docs/*.md": the live site surfaces a
// deliberate subset (quickstart, CLI reference, security, why-not-containers,
// the field notes) with curated cross-page chrome — prev/next ordering, active
// nav, breadcrumb parents — that cannot be inferred from a bare directory walk.
// Reference-only docs (spec, architecture, glossary, …) remain plain markdown
// on GitHub, exactly as the existing gh-pages tree had them.
func Manifest() []Page {
	const v = "v0.3.0"

	docsHome := Crumb{Label: "Docs", Href: "../"}
	fieldNotesParent := Crumb{Label: "Field notes", Href: "../"}
	// Depth-3 pages (docs/integrations/<tool>/) reach the docs home two levels up
	// and the integrations index one level up.
	docsHomeDeep := Crumb{Label: "Docs", Href: "../../"}
	integrationsParent := Crumb{Label: "Integrations", Href: "../"}

	return []Page{
		// ---- Docs home (listing of all docs) ----
		{
			SourceRel:      "README.md",
			OutDir:         "docs",
			Nav:            NavDocs,
			Crumbs:         []Crumb{{Label: "Docs", Current: true}},
			SidebarTitle:   "Documentation",
			GitHubPath:     "docs/README.md",
			IsSectionIndex: true,
			NoTOC:          true,
			Next:           &NavLink{Label: "Next →", Title: "Quickstart", Href: "./quickstart/"},
		},

		// ---- Quickstart ----
		{
			SourceRel:    "quickstart.md",
			OutDir:       "docs/quickstart",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "Quickstart", Current: true}},
			SidebarTitle: "Quickstart",
			SidebarBadge: "5 min",
			GitHubPath:   "docs/quickstart.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Docs home", Href: "../"},
			Next:         &NavLink{Label: "Next →", Title: "CLI Reference", Href: "../cli-reference/"},
		},

		// ---- CLI reference ----
		{
			SourceRel:    "cli-reference.md",
			OutDir:       "docs/cli-reference",
			Nav:          NavCLI,
			Crumbs:       []Crumb{docsHome, {Label: "CLI Reference", Current: true}},
			SidebarTitle: "CLI reference",
			GitHubPath:   "docs/cli-reference.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Quickstart", Href: "../quickstart/"},
			Next:         &NavLink{Label: "Next →", Title: "Security model", Href: "../security/"},
		},

		// ---- Security model ----
		{
			SourceRel:    "security.md",
			OutDir:       "docs/security",
			Nav:          NavSecurity,
			Crumbs:       []Crumb{docsHome, {Label: "Security model", Current: true}},
			SidebarTitle: "Security",
			SidebarBadge: v,
			VersionStamp: v,
			StampNote:    "Updated with each release — items marked in progress are actively being addressed",
			GitHubPath:   "docs/security.md",
			Prev:         &NavLink{Label: "← Previous", Title: "CLI Reference", Href: "../cli-reference/"},
			Next:         &NavLink{Label: "Next →", Title: "Migration & setup", Href: "../migration/"},
		},

		// ---- Migration & setup (privilege separation) ----
		{
			SourceRel:    "migration.md",
			OutDir:       "docs/migration",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "Migration & setup", Current: true}},
			SidebarTitle: "Migration & setup",
			GitHubPath:   "docs/migration.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Security model", Href: "../security/"},
			Next:         &NavLink{Label: "Next →", Title: "Architecture", Href: "../architecture/"},
		},

		// ---- Architecture ----
		{
			SourceRel:    "architecture.md",
			OutDir:       "docs/architecture",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "Architecture", Current: true}},
			SidebarTitle: "Architecture",
			GitHubPath:   "docs/architecture.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Migration & setup", Href: "../migration/"},
			Next:         &NavLink{Label: "Next →", Title: "File layout", Href: "../file-layout/"},
		},

		// ---- File layout ----
		{
			SourceRel:    "file-layout.md",
			OutDir:       "docs/file-layout",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "File layout", Current: true}},
			SidebarTitle: "File layout",
			GitHubPath:   "docs/file-layout.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Architecture", Href: "../architecture/"},
			Next:         &NavLink{Label: "Next →", Title: "`.byn` file format", Href: "../byn-file-format/"},
		},

		// ---- .byn file format + discovery ----
		{
			SourceRel:    "byn-file-format.md",
			OutDir:       "docs/byn-file-format",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "`.byn` file format", Current: true}},
			SidebarTitle: "`.byn` file format",
			GitHubPath:   "docs/byn-file-format.md",
			Prev:         &NavLink{Label: "← Previous", Title: "File layout", Href: "../file-layout/"},
			Next:         &NavLink{Label: "Next →", Title: "Glossary", Href: "../glossary/"},
		},

		// ---- Glossary ----
		{
			SourceRel:    "glossary.md",
			OutDir:       "docs/glossary",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "Glossary", Current: true}},
			SidebarTitle: "Glossary",
			GitHubPath:   "docs/glossary.md",
			Prev:         &NavLink{Label: "← Previous", Title: "`.byn` file format", Href: "../byn-file-format/"},
			Next:         &NavLink{Label: "Next →", Title: "Troubleshooting", Href: "../troubleshooting/"},
		},

		// ---- Troubleshooting ----
		{
			SourceRel:    "troubleshooting.md",
			OutDir:       "docs/troubleshooting",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "Troubleshooting", Current: true}},
			SidebarTitle: "Troubleshooting",
			GitHubPath:   "docs/troubleshooting.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Glossary", Href: "../glossary/"},
			Next:         &NavLink{Label: "Next →", Title: "Why not containers?", Href: "../why-not-containers/"},
		},

		// ---- Why not containers ----
		{
			SourceRel:    "why-not-containers.md",
			OutDir:       "docs/why-not-containers",
			Nav:          NavSecurity,
			Crumbs:       []Crumb{docsHome, {Label: "Why not containers?", Current: true}},
			SidebarTitle: "Why not containers?",
			GitHubPath:   "docs/why-not-containers.md",
			Prev:         &NavLink{Label: "← Previous", Title: "Troubleshooting", Href: "../troubleshooting/"},
			Next:         &NavLink{Label: "Next →", Title: "Field notes", Href: "../field-notes/"},
		},

		// ---- Specification (reference; reachable from docs home) ----
		{
			SourceRel:    "spec.md",
			OutDir:       "docs/spec",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHome, {Label: "Specification", Current: true}},
			SidebarTitle: "Specification",
			GitHubPath:   "docs/spec.md",
		},

		// ---- Integrations index (reference; reachable from docs home) ----
		{
			SourceRel:      "integrations/README.md",
			OutDir:         "docs/integrations",
			Nav:            NavDocs,
			Crumbs:         []Crumb{docsHome, {Label: "Integrations", Current: true}},
			SidebarTitle:   "Integrations",
			GitHubPath:     "docs/integrations",
			IsSectionIndex: true,
			NoTOC:          true,
		},
		// Integration sub-pages (so the integrations index links resolve).
		{
			SourceRel:    "integrations/vscode.md",
			OutDir:       "docs/integrations/vscode",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHomeDeep, integrationsParent, {Label: "VS Code", Current: true}},
			SidebarTitle: "VS Code",
			GitHubPath:   "docs/integrations/vscode.md",
		},
		{
			SourceRel:    "integrations/jetbrains.md",
			OutDir:       "docs/integrations/jetbrains",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHomeDeep, integrationsParent, {Label: "JetBrains", Current: true}},
			SidebarTitle: "JetBrains",
			GitHubPath:   "docs/integrations/jetbrains.md",
		},
		{
			SourceRel:    "integrations/eclipse.md",
			OutDir:       "docs/integrations/eclipse",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHomeDeep, integrationsParent, {Label: "Eclipse", Current: true}},
			SidebarTitle: "Eclipse",
			GitHubPath:   "docs/integrations/eclipse.md",
		},
		{
			SourceRel:    "integrations/ai-agents.md",
			OutDir:       "docs/integrations/ai-agents",
			Nav:          NavDocs,
			Crumbs:       []Crumb{docsHomeDeep, integrationsParent, {Label: "AI coding agents", Current: true}},
			SidebarTitle: "AI coding agents",
			GitHubPath:   "docs/integrations/ai-agents.md",
		},

		// ---- Field notes index (listing) ----
		{
			SourceRel:      "field-notes/README.md",
			OutDir:         "docs/field-notes",
			Nav:            NavFieldNotes,
			Crumbs:         []Crumb{docsHome, {Label: "Field notes", Current: true}},
			SidebarTitle:   "Field notes",
			VersionStamp:   v,
			StampNote:      "Every field note is reviewed and re-stamped at each byn release",
			GitHubPath:     "docs/field-notes",
			IsSectionIndex: true,
			NoTOC:          true,
		},

		// ---- Field notes ----
		{
			SourceRel:    "field-notes/aws-credential-file-takeover.md",
			OutDir:       "docs/field-notes/aws-credential-file-takeover",
			Nav:          NavFieldNotes,
			Crumbs:       []Crumb{fieldNotesParent, {Label: "AWS credential takeover", Current: true}},
			SidebarTitle: "Field notes",
			VersionStamp: v,
			StampNote:    "Re-verified at each release",
			GitHubPath:   "docs/field-notes/aws-credential-file-takeover.md",
		},
		{
			SourceRel:    "field-notes/how-agents-leak-secrets.md",
			OutDir:       "docs/field-notes/how-agents-leak-secrets",
			Nav:          NavFieldNotes,
			Crumbs:       []Crumb{fieldNotesParent, {Label: "How agents leak secrets", Current: true}},
			SidebarTitle: "Field notes",
			VersionStamp: v,
			StampNote:    "Re-verified at each release",
			GitHubPath:   "docs/field-notes/how-agents-leak-secrets.md",
		},
		{
			SourceRel:    "field-notes/real-world-incidents.md",
			OutDir:       "docs/field-notes/real-world-incidents",
			Nav:          NavFieldNotes,
			Crumbs:       []Crumb{fieldNotesParent, {Label: "Real-world incidents", Current: true}},
			SidebarTitle: "Field notes",
			VersionStamp: v,
			StampNote:    "Re-verified at each release",
			GitHubPath:   "docs/field-notes/real-world-incidents.md",
		},
		{
			SourceRel:    "field-notes/tool-comparison.md",
			OutDir:       "docs/field-notes/tool-comparison",
			Nav:          NavFieldNotes,
			Crumbs:       []Crumb{fieldNotesParent, {Label: "Tool comparison", Current: true}},
			SidebarTitle: "Field notes",
			VersionStamp: v,
			StampNote:    "Re-verified at each release",
			GitHubPath:   "docs/field-notes/tool-comparison.md",
		},
	}
}
