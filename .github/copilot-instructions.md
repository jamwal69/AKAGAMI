<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Cybersecurity Toolkit Development Instructions

This is a comprehensive cybersecurity toolkit project with the following architecture:

## Project Structure
- **Backend**: Python FastAPI-based modular security testing platform
- **Frontend**: React.js with Material-UI for modern GUI interface
- **CLI**: Python Click-based command-line interface
- **Modules**: Modular design for different security testing categories

## Development Guidelines
1. **Security First**: Always implement secure coding practices
2. **Modular Design**: Each security testing feature should be a separate module
3. **Error Handling**: Implement comprehensive error handling and logging
4. **Documentation**: Include detailed docstrings and comments
5. **Testing**: Write unit tests for all security modules
6. **Async Operations**: Use async/await for I/O intensive operations
7. **Input Validation**: Validate all user inputs for security
8. **Rate Limiting**: Implement rate limiting for web requests
9. **Legal Compliance**: Include warnings about legal usage only

## Code Style
- Use Python type hints
- Follow PEP 8 standards
- Use descriptive variable and function names
- Implement proper logging throughout the application

## Security Modules Structure
Each security module should follow this pattern:
```python
class SecurityModule:
    def __init__(self):
        self.name = "Module Name"
        self.description = "Module Description"
    
    async def scan(self, target: str, options: dict) -> dict:
        # Implementation
        pass
    
    def validate_target(self, target: str) -> bool:
        # Validation logic
        pass
```
