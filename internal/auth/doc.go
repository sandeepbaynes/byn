// Package auth handles user-facing authentication for the daemon.
//
// Two responsibilities in Slice 1.2:
//
//  1. Reading a password from the terminal in a way that doesn't echo
//     to the screen or persist in shell history (Prompt).
//
//  2. A persistent rate limiter (RateLimiter) that throttles repeated
//     failed-unlock attempts with exponential backoff. State survives
//     daemon restarts so an attacker can't bypass the limit by
//     killing the daemon between guesses.
//
// Biometric (Touch ID / passkey) unlock paths land in Slice 1.3.
package auth
