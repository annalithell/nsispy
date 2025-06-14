from setuptools import find_packages, setup

setup(
    name="nsispy",
    version="0.1.0",
    description="A Python library to inspect and analyze NSIS installers",
    author="Anna Lithell",
    packages=find_packages(),
    install_requires=[
        'pefile==2024.8.26',
        'requests==2.32.3',
    ],
    setup_requires=[
        'pytest-runner==4.4',
    ],
    tests_require=[
        'pytest==7.4.0',
    ],
    test_suite='tests',
    python_requires='>=3.11.9',
    entry_points={
        'console_scripts': [
            'nsispy=nsispy.cli:main',
        ],
    },
)