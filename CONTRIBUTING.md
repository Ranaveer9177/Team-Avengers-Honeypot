# Contributing to Multi-Service Honeypot System

Thank you for considering contributing to this project! This document provides guidelines for contributing.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Relevant log files or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please create an issue with:
- Clear description of the enhancement
- Use case and benefits
- Potential implementation approach (if you have ideas)

### Pull Requests

1. **Fork the repository**
   ```bash
   git fork https://github.com/Ranaveer9177/Team-Avengers-Honeypot.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the coding standards below
   - Add tests for new functionality
   - Update documentation as needed

4. **Run tests**
   ```bash
   pytest tests/
   flake8
   ```

5. **Commit your changes**
   ```bash
   git commit -m "Add: Brief description of changes"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Provide a clear description of changes
   - Reference any related issues
   - Ensure all CI checks pass

## 📝 Coding Standards

### Python Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Maximum line length: 120 characters
- Use meaningful variable and function names
- Add docstrings to all functions and classes

```python
def example_function(param1, param2):
    """
    Brief description of function.
    
    Args:
        param1 (str): Description of param1
        param2 (int): Description of param2
    
    Returns:
        bool: Description of return value
    """
    # Implementation
    pass
```

### Testing

- Write unit tests for all new functionality
- Aim for >80% code coverage
- Use descriptive test names
- Test both success and failure cases

```python
def test_example_function_with_valid_input():
    """Test example_function with valid input"""
    result = example_function("test", 123)
    assert result is True


def test_example_function_with_invalid_input():
    """Test example_function with invalid input"""
    result = example_function(None, -1)
    assert result is False
```

### Security

- **Never** commit secrets, API keys, or passwords
- Use environment variables for sensitive configuration
- Sanitize all user inputs
- Follow secure coding practices
- Report security vulnerabilities privately

### Documentation

- Update README.md if adding features
- Add inline comments for complex logic
- Update configuration examples
- Document API endpoints
- Keep changelog up to date

## 🏗️ Project Structure

```
Team-Avengers-Honeypot/
├── unified_honeypot.py      # Core honeypot server (SSH, HTTP, HTTPS, FTP, MySQL)
├── app.py                   # Flask dashboard with API endpoints & alerting
├── device_detector.py       # Device/client fingerprinting utility
├── boot_menu.py             # Interactive CLI boot menu
├── setup.py                 # Python packaging
├── start.sh                 # Linux/macOS startup script
├── start.ps1                # Windows PowerShell startup script
├── config/                  # Configuration files
├── templates/               # HTML templates
│   ├── unified_dashboard.html   # Dashboard (tabbed sidebar UI)
│   └── login.html               # Web honeypot login page
├── static/
│   ├── css/style.css            # Dashboard styles
│   └── js/dashboard.js          # Dashboard logic
├── tests/                   # Unit tests (16/16 passing)
│   ├── test_app.py              # Dashboard API tests
│   ├── test_config.py           # Config parsing tests
│   ├── test_dashboard.py        # Data sanitization tests
│   ├── test_device_detector.py  # Device detection tests
│   └── test_honeypot.py         # Honeypot logic tests
├── logs/                    # Log files (not in git)
└── pcaps/                   # Packet captures (not in git)
```

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_honeypot.py

# Run specific test
pytest tests/test_honeypot.py::test_fake_filesystem_navigation
```

### Test Coverage

- Core functionality: Required >90% coverage
- Utility functions: Required >80% coverage
- UI/Templates: Optional testing

## 🔧 Development Setup

### Prerequisites

- Python 3.8+
- Git
- Virtual environment tool (venv, virtualenv)

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/Ranaveer9177/Team-Avengers-Honeypot.git
   cd Team-Avengers-Honeypot
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run tests**
   ```bash
   pytest
   flake8
   ```

## 🚀 Feature Development Workflow

1. **Check existing issues** - See if someone is already working on it
2. **Create an issue** - Discuss the feature before implementing
3. **Get feedback** - Wait for maintainer approval
4. **Implement** - Follow coding standards
5. **Test thoroughly** - Add comprehensive tests
6. **Document** - Update all relevant documentation
7. **Submit PR** - Create pull request with clear description

## 📋 Commit Message Guidelines

Use clear, descriptive commit messages:

```
Add: New feature description
Fix: Bug fix description
Update: Changes to existing feature
Docs: Documentation updates
Test: Test additions or changes
Refactor: Code refactoring
Style: Code style changes
Chore: Maintenance tasks
```

Examples:
```
Add: FTP honeypot service handler
Fix: Duplicate method definitions in UnifiedHoneypot
Update: Enhance device detection with DeviceDetector class
Docs: Add Windows installation instructions
Test: Add comprehensive tests for device detection
```

## 🔍 Code Review Process

All pull requests will be reviewed for:

- **Functionality** - Does it work as intended?
- **Testing** - Are there adequate tests?
- **Code Quality** - Does it follow coding standards?
- **Documentation** - Is it well documented?
- **Security** - Are there security concerns?
- **Performance** - Does it impact performance?

## 🎯 Priority Areas for Contribution

### High Priority
- Additional service honeypots (SMTP, DNS, etc.)
- Enhanced attack pattern detection
- Machine learning integration
- Real-time alerting system

### Medium Priority
- Additional tests
- Performance optimizations
- UI/UX improvements
- Documentation enhancements

### Low Priority
- Code refactoring
- Minor bug fixes
- Style improvements

> **Note:** As of v4.0, the following obsolete files have been removed: `ssh_honeypot.py`, `ssh_dashboard.py`, `app_test.py`, `advanced_honeypot.py`, `advanced_honeypot_server.py`. Do not recreate these files.

## 📚 Resources

- [Python Documentation](https://docs.python.org/3/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Paramiko Documentation](https://www.paramiko.org/)
- [pytest Documentation](https://docs.pytest.org/)

## 💬 Communication

- **Issues** - For bug reports and feature requests
- **Pull Requests** - For code contributions
- **Discussions** - For questions and ideas

## 📜 License

By contributing, you agree that your contributions will be licensed under the same license as the project.

## 🙏 Recognition

Contributors will be recognized in:
- README.md acknowledgments
- CHANGELOG.md entries
- GitHub contributors page

Thank you for contributing to the Multi-Service Honeypot System! 🎉
