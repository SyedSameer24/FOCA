from setuptools import setup, find_packages

setup(
    name="foca-cli",
    version="2.4.0",
    description="FOCA CLI: Metadata & Full Organizational OSINT Suite",
    py_modules=["main"],
    packages=find_packages(include=["foca_core*"]),
    entry_points={
        "console_scripts": [
            "foca=main:main",
        ],
    },
)
