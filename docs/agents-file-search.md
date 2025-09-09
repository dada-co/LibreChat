# Managing File Search Tools and Vector Stores

LibreChat's Agents API lets you attach a `file_search` tool to an agent and connect it to one or more vector stores. This guide shows how to create and update agents using this tool.

## List available tools
Before configuring an agent, check what tools are available:

```bash
curl -X GET "http://localhost:3080/api/agents/tools" \
  -H "Authorization: Bearer $TOKEN"
```

## Create an agent with File Search and a vector store

```bash
curl -X POST "http://localhost:3080/api/agents" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ronit kfir",
    "provider": "openAI",
    "model": "o4-mini",
    "tools": ["file_search"],
    "tool_resources": {
      "file_search": {
        "vector_store_ids": ["vs_68bf32debaa881918a27f77e54c24d95"]
      }
    }
  }'
```

## Update an existing agent to add File Search

```bash
curl -X PATCH "http://localhost:3080/api/agents/{agent_id}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tools": ["file_search"],
    "tool_resources": {
      "file_search": {
        "vector_store_ids": ["vs_68bf32debaa881918a27f77e54c24d95"]
      }
    }
  }'
```

## Add a new vector store to an existing File Search tool
If the agent already uses `file_search`, send a patch with the full list of vector stores (existing and new):

```bash
curl -X PATCH "http://localhost:3080/api/agents/{agent_id}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_resources": {
      "file_search": {
        "vector_store_ids": ["vs_existing", "vs_new"]
      }
    }
  }'
```

### Request body fields
* `tools` – array of tool names (`["file_search"]`).
* `tool_resources.file_search.vector_store_ids` – IDs of vector stores linked to the File Search tool.

The schema for `file_search` resources is defined in the API and includes the optional `vector_store_ids` array.

