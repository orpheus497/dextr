#!/usr/bin/env python3
"""
Setup script for dextr - Secure Archiving & Encryption System
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='dextr',
    version='1.2.0',
    description='Secure archiving and encryption system with multi-layer AEAD protection',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='orpheus497',
    author_email='',
    url='',
    packages=find_packages(),
    install_requires=requirements,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'dextr=dextr.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Operating System :: OS Independent',
        'Environment :: Console',
    ],
    keywords='encryption cryptography backup security archiving aead library api',
    project_urls={
        'Source': '',
        'Bug Reports': '',
    },
)
