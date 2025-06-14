from setuptools import setup, find_packages

setup(
    name='pcapdump',
    version='0.0.17',
    packages=find_packages(),
    install_requires=[
        'pyshark',
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'pcapdump=src.main:main',
        ],
    },
)