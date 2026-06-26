---
name: cs2-ida-analysis
description: Analyze Counter-Strike 2 / Source 2 native binaries in IDA Pro using MCP tools. Use for CS2 crash analysis, static IDA annotation, high-confidence renames/comments/types, crash-path recovery, behavior summaries, schema dump assisted type recovery, and reference-source assisted analysis with hl2sdk-cs2, hl2sdk, or cstrike15_src.
---

# CS2 IDA Analysis

Use this skill for CS2 / Source 2 reverse engineering in IDA Pro. Work in one of two modes:

- `Crash analysis`: recover a specific crash path and identify the most likely root cause.
- `Static annotation`: improve IDA names, comments, and types without requiring a crash context.

Treat IDA, crash context, and MCP tool results as the source of truth. Use schema dumps and Source reference code only as auxiliary evidence.

## Required Intake

Before reverse engineering, determine the mode.

Use `Crash analysis` when the user provides a crash address, exception context, call stack, minidump notes, module offset, or asks for a crash root cause.

Use `Static annotation` when the user asks to clean up, annotate, type, rename, map, or understand code without a concrete crash.

If the mode is ambiguous, ask:

```text
Which mode should I use?

1. Crash analysis: analyze a specific crash path and root cause.
2. Static annotation: improve IDA names, comments, and types for a selected scope.
```

Then ask:

```text
Do you have local auxiliary CS2 / Source-related reference data that I can use during analysis?

Schema dump example:
D:\GithubProjects\GameTracking-CS2\DumpSource2\schemas

Reference source examples:
D:\GithubProjects\hl2sdk-cs2
D:\GithubProjects\hl2sdk
D:\GithubProjects\cstrike15_src

Report preference:
- full report.md
- concise report.md
- no report, IDA annotations and renames only

If yes, please provide the available path(s).
If no auxiliary data is available, I will continue with IDA-only analysis.
```

Do not begin reverse engineering until the mode, auxiliary data availability, and report preference are known, unless the user explicitly says to proceed with defaults.

Default assumptions if the user says to proceed with defaults:

- Mode: infer from the request; use `Static annotation` if no crash context exists.
- Auxiliary data: none.
- Report: concise `report.md`.

## Evidence Priority

Use this priority order:

1. IDA decompilation, disassembly, xrefs, strings, imports, exports, names, comments, types, data references, and crash context.
2. Matching CS2 / Source 2 schema dump data.
3. Matching `hl2sdk-cs2`, `hl2sdk`, `cstrike15_src`, or similar reference source.
4. General Source 2 / CS2 domain knowledge.

Use lower-priority evidence to guide investigation, not to override binary evidence.

If schema or source conflicts with the binary, prefer the binary and record the conflict in IDA comments or the report when relevant.

## Auxiliary Data Rules

Use schema dumps to identify class names, field names, field offsets, inheritance, enums, flags, handles, resource types, and networked fields. Apply schema-backed names only when offsets and usage match the analyzed binary.

Use reference source to recognize naming conventions, interface names, virtual method families, service access patterns, function signatures, handles, entity concepts, resource patterns, strings, vectors, and CUtl-style containers. Apply source-derived names only when supported by binary evidence such as strings, xrefs, imports, vtable slot usage, schema data, field access patterns, or call signatures.

Inspect only the relevant schema/source files needed for the current scope.

## CS2 / Source 2 Orientation

Common module hints:

- `client.dll`: client entities, prediction, input, view, HUD/UI, client-side rendering state.
- `server.dll`: server entities, game rules, player state, weapons, damage, bots, simulation.
- `engine2.dll`: engine services, networking, host state, frame loop, commands.
- `schemasystem.dll`: runtime schema metadata.
- `tier0.dll` / `tier1.dll`: platform utilities, memory, logging, interfaces, strings, containers.
- `resourcesystem.dll`: resource loading, handles, references, streaming, lifetime.
- `panorama.dll`: UI panels, events, layout, scripts, UI resource state.
- `rendersystem*.dll` and material/resource modules: render resources, materials, meshes, textures, scene data.

Common crash or lifetime themes:

- Null or stale entity/component pointer.
- Invalid entity handle, serial, index, or resource handle.
- Schema field accessed on the wrong object type or stale object.
- Vtable call through a destroyed or wrong-type object.
- Resource unloaded, partially initialized, or used on the wrong thread.
- Callback, job, UI event, prediction path, or render path references destroyed state.
- Networked or schema-backed data reaches native code with unexpected count, index, or state.

## Shared Rules

- Use IDA Pro and available MCP tools as the primary source of truth.
- Inspect decompilation first when available.
- Inspect disassembly when decompilation is ambiguous or hides important behavior.
- Add IDA comments for every high-confidence finding.
- Rename all materially useful high-confidence symbols within the selected scope.
- Prioritize renames that clarify crash paths, object identity, schema-backed fields, handles, ownership, subsystem boundaries, API/interface roles, and future xrefs.
- Skip low-value temporaries or symbols whose renamed form does not improve analysis.
- Change variable, argument, return, pointer, array, struct, enum, and function-pointer types when existing types are misleading.
- Prioritize types that clarify the current mode: schema classes, entity pointers, handles, vtables, CUtl-style containers, arrays, resource handles, panel pointers, callbacks, jobs, and interfaces.
- Never convert number bases manually. Use the `int_convert` MCP tool for every address, RVA, VA, offset, decimal, hexadecimal, binary, or other base conversion.
- Do not claim a root cause unless supported by IDA evidence, crash context, matching schema data, matching source data, or deterministic scripts that model recovered logic.
- Do not patch binaries, write hooks, or present a fix as proven unless the root cause is evidence-backed.
- Do not run broad brute force, random search, or speculative scripts.

## Rename And Comment Policy

Be proactive where certainty and usefulness are high. Rename materially useful symbols when one or more are true:

- Schema class or field names match observed offsets and object usage.
- Reference source names match binary behavior, vtable usage, signatures, strings, or schema-backed types.
- Strings identify a Source 2 subsystem, class, interface, resource, event, command, or error path.
- Imports, interface calls, or API calls reveal behavior.
- Xrefs show a function is consistently used for one purpose.
- Vtable, RTTI, constructor, destructor, or schema metadata identifies an object type.
- Field offsets are repeatedly accessed in a way that matches schema data or stable usage.
- Crash context or static data flow shows a parameter or local variable directly participates in important behavior.

Do not rename just to increase rename count. A rename should make navigation, xrefs, type recovery, crash-path reasoning, or future review materially better.

Write IDA comments as short, reviewable evidence statements:

- Prefer one sentence per comment line.
- Keep each line focused on one evidence-backed fact.
- Split multiple facts at the same address into separate comment lines.
- Comment pointer provenance, schema/field matches, null checks, stale-handle checks, bounds checks, virtual calls, lifetimes, refcounts, release paths, jobs, callbacks, thread-sensitive regions, safe/unsafe branches, and subsystem boundaries.

Good:

```text
// HIGH: rcx is CCSPlayerPawn* by schema-backed field use.
// HIGH: Crash reads m_pWeaponServices with no null check.
// HIGH: Field offset matches CCSPlayerPawn::m_pWeaponServices in the provided schema dump.
```

## Crash Analysis Mode

Objective:

- Locate the crash.
- Recover the crash path.
- Identify the involved subsystem, object, field, resource, entity, handle, interface, vtable, callback, or job.
- Identify the most likely failure class, such as null dereference, use-after-free, invalid vtable, invalid handle, bad schema field access, resource lifetime bug, thread/order bug, or bad asset state.
- Support every conclusion with evidence.

Workflow:

1. Collect crash context: module, image base, crash address, exception code, crashing instruction, registers, thread, call stack, and logs.
2. Use `int_convert` for any required VA/RVA/offset/base conversion.
3. Locate the crashing function and basic block in IDA.
4. Inspect decompilation near the crash.
5. Inspect disassembly when needed and comment the faulting instruction.
6. Identify the Source 2 subsystem and object type using strings, xrefs, interfaces, schema data, vtables, field offsets, and call context.
7. Trace data flow backward from the crashing pointer, handle, index, field, resource, or object.
8. Trace callers and callees to recover the crash path.
9. Recover relevant types and apply schema/source-backed names only when supported.
10. Inspect boundary conditions: null checks, handle serial checks, bounds checks, resource state checks, thread ownership checks, and vtable validation.
11. Apply materially useful high-confidence IDA renames, comments, and type corrections throughout the crash path.
12. Use small deterministic scripts only to replay recovered address math, table indexing, bit flags, schema offset matching, or decoded constants.
13. If requested, write `report.md`.

Crash report content:

- Full report: crash context, auxiliary data paths, renamed symbols, type changes, step-by-step crash path, most likely root cause, confidence, evidence versus hypotheses, helper scripts or pseudocode, unresolved questions, and validation steps.
- Concise report: crash context, most likely root cause, confidence, key evidence, important IDA renames/comments/types, auxiliary data used, and remaining blocker if unresolved.

## Static Annotation Mode

Objective:

- Improve the IDA database for a selected CS2 / Source 2 scope.
- Recover useful behavior, structure, field usage, interfaces, object flow, ownership boundaries, and subsystem roles.
- Avoid root-cause language unless the user switches to `Crash analysis` or a concrete crash path is recovered.

If the user does not provide a scope, ask:

```text
What static annotation scope should I work on?

Examples:
- current function
- function at <address>
- all xrefs around <string/global/vtable>
- subsystem such as weapons, player pawn, schema system, resources, panorama, prediction, networking
- address range or function list
```

If the user says to proceed with defaults, start from the current IDA function or the most relevant function implied by the request.

Workflow:

1. Confirm static annotation scope.
2. Survey strings, imports, xrefs, exports, vtables, RTTI/schema references, and nearby functions in scope.
3. Inspect decompilation of each high-value function.
4. Inspect disassembly where pseudocode is unclear.
5. Match field offsets and class usage against schema data when available.
6. Match interface and helper behavior against reference source only when binary behavior supports it.
7. Rename materially useful high-confidence functions, globals, vtables, locals, arguments, labels, fields, structs, and constants.
8. Apply type corrections that clarify call signatures, object pointers, arrays, handles, containers, callbacks, and return values.
9. Add concise one-sentence-per-line comments explaining evidence-backed facts.
10. Prefer comments at key decision points, object loads, field accesses, virtual calls, resource/handle resolution, constructors/destructors, and ownership boundaries.
11. Track uncertain findings as hypotheses only when useful.
12. If requested, write `report.md`.

Static annotation report content:

- Full report: selected scope, auxiliary data paths, renamed symbols, type changes, schema/source matches, important comments, behavior summary, recovered structure, uncertainty, and suggested next annotation targets.
- Concise report: selected scope, most important renames/types, key schema/source matches, behavior summary, recovered structure highlights, and uncertainty or remaining blockers.
- No report: rely on IDA comments, names, and type changes as the deliverable.

## Final Response

For `Crash analysis` with a report:

```text
Analysis complete.

Mode: Crash analysis
Most likely root cause: <short summary or not recovered>
Confidence: <high / medium / low>

Schema dump used: <yes/no, path if yes>
Reference source used: <yes/no, path(s) if yes>
Report created: <full / concise>

I created report.md with the findings, IDA annotations, renamed symbols, schema/source references, and steps taken.
```

For `Static annotation` with a report:

```text
Analysis complete.

Mode: Static annotation
Scope: <scope summary>
Behavior summary: <short behavior summary>
Recovered structure: <short type/layout/interface summary>
Uncertainty: <short uncertainty summary or "none noted">

Schema dump used: <yes/no, path if yes>
Reference source used: <yes/no, path(s) if yes>
Report created: <full / concise>

I created report.md with the annotation summary, renamed symbols, type changes, comments, and schema/source references.
```

When no report was requested:

```text
Analysis complete.

Mode: <Crash analysis / Static annotation>
Result: <root-cause summary for Crash analysis, or annotation/behavior summary for Static annotation>
Confidence: <high / medium / low, if applicable>

Schema dump used: <yes/no, path if yes>
Reference source used: <yes/no, path(s) if yes>
Report created: no, per user preference.

IDA annotations and renames were applied where confidence was sufficient.
```
