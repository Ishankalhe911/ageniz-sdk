from setuptools import setup, find_packages

setup(
    name="agenizai-sdk",
    version="2.3.0",
    author="Ishan Kalhe",
    author_email="ishankalhe1@gmail.com",
    description="Zero-trust ML Risk Oracle and Firewall for Algorand AI Agents",
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Ishankalhe911/ageniz-sdk",
    packages=find_packages(),
    install_requires=[
        "py-algorand-sdk>=2.0.0",
        "requests>=2.25.0",
        "python-dotenv>=1.0.0"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)