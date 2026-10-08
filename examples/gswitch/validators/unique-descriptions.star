def validate(config):
    seen = {}
    interfaces = config.get("interfaces", {})
    for name in sorted(interfaces):
        description = interfaces[name].get("description", "")
        if type(description) != "string":
            return "interface %s description must be a string" % name
        if not description:
            continue
        if description in seen:
            return "description %r is used by both %s and %s" % (description, seen[description], name)
        seen[description] = name
    return None
