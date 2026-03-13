---
name: vault-mdl-analyzer
description:
  Analyze Veeva Vault configuration by extracting and interpreting Metadata Definition Language (MDL) files. 
  Use this skill to fetch specific component configurations, perform impact analysis, and answer questions about Vault setup using raw metadata.
---

# Veeva Vault MDL Analyzer

This skill provides a deterministic framework for extracting, analyzing, and explaining Veeva Vault configuration using Metadata Definition Language (MDL). It ensures that the AI remains grounded in actual metadata rather than making assumptions about Vault configuration.

## Core Objective
To provide high-fidelity analysis of Veeva Vault components by executing precise API queries and interpreting the resulting MDL configuration files.

## Deterministic Workflow

### 1. Initialization and Context Gathering
When a user asks about a Vault component (e.g., an Object, Lifecycle, or Document Type), the agent MUST first identify the technical name or exact label of the component.
- **Action**: Use `scripts/flow_controller.py` with the `--target` and `--path` flags.
- **Path Parameter**: The `--path` parameter is **mandatory** and must always be the **absolute path** of the current working directory.
- **Search Logic**: The script handles searching via an internal VQL query. Note that there is no fallback for custom VQL actions; all metadata retrieval must be performed using this script and flag.
- **Authentication**: Inform the user that a browser-based login may be initiated and they should check their local browser window. This process requires access to a local port (default 8000) for the PKCE callback.
- **Exact Match Requirement**: The `--target` value must be an **exact match** for either the component's **Label** or its **Technical Name**. If a search returns no results, try the other identifier (e.g., if "Product Object" fails, try "Product").
- **Command Template**: `python3 scripts/flow_controller.py --vault-url <VAULT_URL> --username <USER> --target "<EXACT_COMPONENT_NAME_OR_LABEL>" --path <ABSOLUTE_PATH_TO_WORKING_DIRECTORY> [--force]`
    - *Note: Only include `--force` if a refresh is explicitly requested or the local file is stale.*
- **Ambiguity Handling**: If multiple components match the target, the script extracts all into their respective type directories. The agent MUST check *all* subdirectories within the `vault_name` folder for files matching the sanitized label. If multiple files are found, ask the user for clarification before proceeding.

### 2. Metadata Extraction
The agent must ensure the raw MDL is available for analysis.
- **Rule**: Never analyze a component based on its name alone; always extract the MDL first.
- **Rule**: If the MDL file already exists in the local directory structure, use it.
    - **Path Structure**: `vault_name/component_type/Sanitized_Label.MDL`
    - **vault_name Derivation**: The subdomain of the `--vault-url` where any character that is not a letter, number, or underscore is replaced by an underscore (e.g., `https://my-vault.veevavault.com` becomes `my_vault`).
    - **Label Sanitization**: File names use the component **Label** (sanitized). The sanitization process replaces the following characters with underscores: `\ / * ? : " < > |` (e.g., "Product / Type A" becomes `Product _ Type A.MDL`).

### 3. Structural Analysis
Once the MDL is retrieved, the agent must parse it to answer the user's specific question.
- **Directory Resolution**: Use the exact `component_type__v` returned by the tool as the directory name (e.g., `Objectlifecycle`, `Doclifecycle`, `Workflow`) rather than generic names.
- **Rule**: Identify the component type from the `RECREATE` header (e.g., `RECREATE Object product__v`) and look for the specific attribute blocks relevant to that type:
    - **Objects**: Look for `fields`, `relationships`, and `indexes`.
    - **Doc Types**: Look for `lifecycle__v`, `templates`, and `fields`.
    - **Lifecycles**: Look for `states`, `user_actions`, and `entry_criteria`. Note that these attributes are typically nested within individual `state` blocks.
    - **Workflows**: Look for `steps`, `variables`, and `tasks`.
    - **Picklists**: Look for `picklist_values`.
- **Constraint**: If the MDL references another component (e.g., a shared field or a specific lifecycle), the agent SHOULD proactively ask or attempt to extract that secondary component's MDL if necessary for a complete answer.

### 4. Jargon-Free Explanation
Translate the technical MDL syntax into plain English.
- **Metadata vs. MDL Content**: Distinguish between **search metadata** (e.g., `component_type__v`, `component_name__v`) returned by the tool and the **MDL content** found inside the extracted file (e.g., `RECREATE Object product__v { ... }`). **Warning**: Do not look for search fields like `component_type__v` or `label__v` inside the .MDL file content; use the `RECREATE` header to identify the type.
- **Mapping**: 
    - `active: true/false`: Whether the feature is currently turned on.
    - `required: true/false`: Whether the user must provide this information.

## Rules to Prevent Deviation

1. **Grounding Requirement**: Do not describe how a Vault feature "typically" works. Only describe how it is configured in the specific MDL retrieved.
2. **No Hallucinations**: If a query returns no results or the MDL extraction fails, report the failure immediately. Do not guess the configuration.
3. **Idempotency & Freshness**: Use the local cache created by `flow_controller.py` to minimize API calls. However, if the local file appears stale (check the modified date), ask the user: "I have a local copy from [Date]; should I refresh it from the Vault?"
4. **Security First**: Never print or log the `SESSION_ID_TOKEN`. Use the `auth_handler.py` to manage tokens silently.
5. **Tool Precision**: Always provide the full `--vault-url` and ensure `--target` is wrapped in quotes to handle spaces in labels.
6. **Troubleshooting**: If authentication errors persist (e.g., due to a corrupted or stale session), use the `--clear-token` flag in `flow_controller.py` to reset the cached token.

## Resource Usage Guide

- **`scripts/flow_controller.py`**: The **mandatory** entry point for all operations. Handles searching via internal VQL, authentication coordination, and file-system organization. Note: There is no fallback for custom VQL queries; all operations must use the `--target` search flow.
- **`scripts/auth_handler.py`**: Manages the authentication lifecycle. Do not call this directly; `flow_controller.py` handles it.

## Example Interactions

**User**: "Tell me how the 'Product' object is configured."
**Agent Action**: 
1. Run `python3 scripts/flow_controller.py --vault-url https://myvault.veevavault.com --username user@veeva.com --target "Product" --path "/Users/DanielRodriguez/Code/vault-mdl-analyzer"`
2. Read the resulting `.MDL` file in the `myvault/Object` directory.
3. Explain the attributes, fields, and relationships found in the MDL.

**User**: "Check if the 'Claims' lifecycle has any mandatory fields."
**Agent Action**:
1. Run `python3 scripts/flow_controller.py --vault-url https://myvault.veevavault.com --username user@veeva.com --target "Claims" --path "/Users/DanielRodriguez/Code/vault-mdl-analyzer"`
2. Identify the `Objectlifecycle` or `Doclifecycle` type.
3. Parse the MDL specifically for `required: true` markers in the state configurations.
