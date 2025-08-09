KNOWLEDGE_BASE = {
    "Input Validation": {
        "title": "Input Validation Best Practices",
        "content": "Input validation is a critical security control that protects against a variety of attacks, including Cross-Site Scripting (XSS), SQL Injection, and buffer overflows. All user-supplied input should be treated as untrusted. Implement robust input validation on both the client-side and server-side. Use allow-lists (whitelisting) to define acceptable input patterns and reject all other input. Sanitize and encode output to prevent XSS. Use parameterized queries (prepared statements) to prevent SQL Injection."
    },
    "Authentication and Session Management": {
        "title": "Secure Authentication and Session Management",
        "content": "Implement strong authentication mechanisms to protect user accounts. Enforce strong password policies, including minimum length, complexity, and rotation. Use multi-factor authentication (MFA) to provide an additional layer of security. Session management should be secure, with session IDs generated using a cryptographically secure random number generator. Sessions should have a reasonable timeout and be invalidated upon logout."
    },
    "Access Control": {
        "title": "Principle of Least Privilege",
        "content": "The principle of least privilege dictates that users and system components should only have access to the resources and permissions necessary to perform their tasks. Implement granular access control policies to enforce this principle. Use role-based access control (RBAC) to manage permissions for different user roles. Regularly review and audit user permissions to ensure they are still appropriate."
    },
    "Error Handling and Logging": {
        "title": "Secure Error Handling and Logging",
        "content": "Error messages should be generic and not reveal sensitive information about the application's inner workings, such as database schemas or file paths. Log all security-relevant events, including successful and failed authentication attempts, access control decisions, and input validation failures. Logs should be protected from unauthorized access and tampering."
    }
}
