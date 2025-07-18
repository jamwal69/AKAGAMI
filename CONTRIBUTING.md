# Contributing to AKAGAMI

We welcome contributions to the AKAGAMI cybersecurity toolkit! This document provides guidelines for contributing to the project.

## 🤝 Ways to Contribute

- **Security Modules**: Add new security testing modules
- **Bug Fixes**: Fix issues and improve stability  
- **Documentation**: Improve docs, examples, and guides
- **Testing**: Write tests and improve test coverage
- **UI/UX**: Enhance the GUI and CLI interfaces
- **Performance**: Optimize scanning speed and resource usage

## 🚀 Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/akagami.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes following our coding standards
5. Test your changes thoroughly
6. Commit with descriptive messages
7. Push to your fork: `git push origin feature/your-feature-name`
8. Create a Pull Request

## 📝 Coding Standards

### Python Code
- Follow PEP 8 style guidelines
- Use type hints for all functions
- Include comprehensive docstrings
- Write unit tests for new modules
- Use async/await for I/O operations

### Security Module Structure
```python
class YourSecurityModule:
    def __init__(self):
        self.name = "Your Module Name"
        self.description = "Detailed description of what it does"
    
    async def scan(self, target: str, options: dict = None) -> dict:
        """
        Main scanning method
        
        Args:
            target: The target URL or domain
            options: Optional configuration parameters
            
        Returns:
            dict: Scan results with vulnerabilities, metadata, etc.
        """
        # Implementation here
        pass
    
    def validate_target(self, target: str) -> bool:
        """Validate the target before scanning"""
        # Validation logic
        pass
```

### Frontend Code (React/TypeScript)
- Use TypeScript for type safety
- Follow React best practices
- Use functional components with hooks
- Implement proper error handling
- Write component tests

## 🧪 Testing

- Write unit tests for all new modules
- Test CLI commands and API endpoints
- Test GUI functionality
- Include edge cases and error conditions
- Ensure all tests pass before submitting PR

## 📋 Pull Request Guidelines

### PR Title Format
```
[Type] Brief description of changes

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- test: Adding tests
- refactor: Code refactoring
- style: Code style changes
- perf: Performance improvements
```

### PR Description Template
```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] Unit tests added/updated
- [ ] Manual testing completed
- [ ] All existing tests pass

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Proper input validation
- [ ] Safe for production use

## Legal Compliance
- [ ] Only targets authorized systems
- [ ] Includes appropriate warnings
- [ ] Follows responsible disclosure
```

## 🔒 Security Considerations

- **Never include real vulnerability exploits** that could cause harm
- **Always include rate limiting** in scanning modules
- **Implement proper input validation** for all user inputs
- **Add warnings** about legal usage in documentation
- **Follow responsible disclosure** for any vulnerabilities found
- **Respect robots.txt** and other access restrictions

## 📚 Documentation

- Update README.md if adding new features
- Add docstrings to all new functions/classes
- Include usage examples in CLI help
- Update API documentation
- Add security warnings where appropriate

## 🏷️ Module Categories

When adding new modules, categorize them properly:

- **🔍 Reconnaissance**: Information gathering and mapping
- **🚨 Vulnerability Detection**: Finding security flaws
- **🔐 Authentication & Authorization**: Auth-related testing
- **💉 Injection Testing**: Various injection vulnerabilities
- **⚡ Logic Flaws**: Business logic and timing issues
- **🌐 Network Security**: Network-level testing
- **🔓 Cryptography**: Crypto analysis and testing
- **📱 Mobile Security**: Mobile app testing
- **🕵️ Digital Forensics**: Forensic analysis tools

## ❓ Questions?

- Create an issue for questions
- Check existing documentation
- Review the CLI help: `python cli.py cheats`

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to AKAGAMI! 🚀
