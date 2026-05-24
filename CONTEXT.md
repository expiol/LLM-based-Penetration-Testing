# LLM-Based Penetration Testing

This context describes the autonomous CTF killchain runtime: a Planner proposes work, a Router dispatches it to Persona workers, and Tool capabilities execute bounded evidence-gathering steps.

## Language

**Killchain Run**:
One attempt to solve or assess a challenge from objective through persisted artifacts.
_Avoid_: session, job

**Run State**:
The durable facts, todos, evidence, and terminal status accumulated during a Killchain Run.
_Avoid_: global state, context blob

**Planner Todo**:
A high-level killchain task proposed by the Planner and consumed by the Router.
_Avoid_: task, action item

**Dispatch Intent**:
The structured routing meaning of a Planner Todo, including profile, required capability, target references, and completion contract.
_Avoid_: routing metadata, context hints

**Persona Worker**:
A specialized worker role that turns one Planner Todo into one or more Tool capability executions or a deterministic validation.
_Avoid_: agent, service

**Tool Capability**:
A named execution capability exposed to Persona workers and backed by a concrete tool plugin.
_Avoid_: tool API, command wrapper

**Tool Workspace**:
The protected filesystem and process environment where a Tool capability executes against challenge files.
_Avoid_: sandbox, temp dir

**Run Artifact**:
A persisted file or JSON record produced by a Killchain Run, batch run, monitor, or audit.
_Avoid_: output blob

**RAG Status**:
The public and audit-safe retrieval state for writeup augmentation during a Killchain Run.
_Avoid_: RAG payload, retrieval dict

## Relationships

- A **Killchain Run** owns exactly one **Run State**.
- A **Planner Todo** carries one **Dispatch Intent**.
- A **Persona Worker** consumes one **Planner Todo** at a time.
- A **Persona Worker** may execute one or more **Tool Capabilities**.
- A **Tool Capability** executes inside a **Tool Workspace**.
- A **Killchain Run** produces many **Run Artifacts**.
- **RAG Status** is recorded inside **Run State** and projected into **Run Artifacts**.

## Example Dialogue

> **Dev:** "Should this **Planner Todo** mention `png.inspect` in free text?"
> **Domain expert:** "No. Put that requirement in the **Dispatch Intent** so the Router and **Persona Worker** can make the same decision without parsing prose."

## Flagged Ambiguities

- "task" has been used for both **Planner Todo** and low-level tool execution; resolved: use **Planner Todo** for Planner/Router work and **Tool Capability** for executable tool behavior.
- "artifact" has been used for challenge files and persisted run outputs; resolved: use **Run Artifact** for persisted runtime outputs, and describe original inputs as challenge files.
