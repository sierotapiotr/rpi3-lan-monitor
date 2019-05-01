from setuptools import setup

setup(
    name='monitor',
    packages=['monitor'],
    include_package_data=True,
    install_requires=[
        'flask',
        'sqlalchemy',
        'flask_login',
        'flask_wtf',
        'flask_bootstrap',
        'python-nmap',
        'wtforms',
        'database'
    ],
)
