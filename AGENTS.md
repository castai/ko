## Code style guide

### No verbose comments

This is a service, not a library: godoc conventions do not apply. Comments are allowed only inside function and method bodies, and only to explain important code paths that are not clear by themselves. Never write comments on top of functions, types, constants, fields, or any other declaration — make the names carry the meaning.
