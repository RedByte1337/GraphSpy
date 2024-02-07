from setuptools import setup

with open("README.md", 'r', encoding='utf-8') as f:
    readme = f.read()

with open("GraphSpy/version.txt", 'r', encoding='utf-8') as f:
    __version__ = f.read()

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [x.strip() for x in f.readlines()]

setup(
    name='GraphSpy',
    version=__version__,
    author='RedByte1337',
    url='https://github.com/RedByte1337/GraphSpy',
    description="Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI",
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=requirements,
    package_data={'': ['static/**/*','templates/*','version.txt']},
    include_package_data=True,
    packages=[
        "GraphSpy"
    ],
    entry_points={
        "console_scripts": ["graphspy=GraphSpy.GraphSpy:main"],
    }
)