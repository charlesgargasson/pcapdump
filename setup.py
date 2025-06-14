from setuptools import setup, find_packages

setup(
    name='pcapdump',
    version='1.0.0',
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