# Naming and tagging standard

## Naming convention

- Use lowercase kebab-case for repository, directory, and Python module names where practical.
- Prefer descriptive names that map directly to AWS resources or scenario categories.
- Keep identifiers consistent across Terraform modules and Python packages.

## Tagging convention for future AWS resources

Required tags for any future AWS resources:

- project = sentinelops
- environment = dev|test|prod
- owner = cloud-security
- cost-center = optional or project-specific
- managed-by = terraform
- phase = 0|1|2|...
- created-by = sentinelops-agent

## Guardrails

- Avoid resource names that leak customer information or secrets.
- Keep environment boundaries explicit and separate.
- Never rely on default AWS tags alone for security or operational controls.
