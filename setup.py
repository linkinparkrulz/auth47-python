"""
setup.py for auth47 library
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="auth47",
    version="1.2.1",
    author="Your Name",
    author_email="your.email@example.com",
    description="A Python implementation of the Auth47 protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/auth47-python",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core dependencies - minimal for basic functionality
    ],
    extras_require={
        "full": [
            "bitcoinlib>=0.6.14",  # For Bitcoin message verification
            "bip47>=0.1.0",  # For payment code support
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "mypy>=0.990",
            "pylint>=2.15.0",
        ],
    },
    keywords="bitcoin auth47 authentication bip47 paynym",
)
