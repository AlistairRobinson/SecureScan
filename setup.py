import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="SecureScan",
    version="1.0",
    author="Alistair Robinson",
    description="A private, secure service discovery protocol package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AlistairRobinson/SecureScan",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)