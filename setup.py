import os
import setuptools

def read(file_path):
    here = os.path.abspath(os.path.dirname(__file__))

    with open(os.path.join(here, file_path), encoding='utf-8') as f:
        return f.read()

def get_version(file_path):
    for line in read(file_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]

install_requires = [
    'numpy >= 1.24.2',
    'pandas >= 1.5.3'
]

setuptools.setup(
        name="bvmlib",
        version=get_version('bvmlib/__init__.py'),
        author="Gabriel Henrique Lopes Gomes Alves Nunes",
        author_email="contact@nunesgh.com",
        url="https://github.com/nunesgh/bvm-library",
        project_urls={
            "Bug Tracker": "https://github.com/nunesgh/bvm-library/issues",
            "Documentation": "https://nunesgh.github.io/bvm-library/",
            "Source Code": "https://github.com/nunesgh/bvm-library",
        },
        description="Bayes Vulnerability for Microdata library",
        long_description=read("README.md"),
        long_description_content_type='text/markdown',
        packages=setuptools.find_packages(),
        install_requires=install_requires,
        python_requires='>=3.10.6'
)
