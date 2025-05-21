from setuptools import find_packages, setup

setup(
    name="nsispy",
    version="0.1.0",
    description="A Python library to inspect and analyze NSIS installers",
    author="Anna Lithell",
    packages=find_packages(),
    install_requires=[],
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
    python_requires='>=3.11.9',
    entry_points={
        'console_scripts': [
            'nsispy=nsispy.cli:main',
        ],
    },
)