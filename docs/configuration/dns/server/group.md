---
icon: material/new-box
---

# Group

### Structure

```json
{
  "dns": {
    "servers": [
      {
        "type": "group",
        "tag": "dns-group",

        "servers": [
          "dns-a",
          "dns-b"
        ]
      }
    ]
  }
}
```

### Fields

#### servers

==Required==

List of DNS server tags to include in this group.

Restrictions:

- A group cannot contain another group.
- A group cannot contain a `fakeip` server.

When queried, all servers in the group are queried concurrently, and the first successful response is returned.
