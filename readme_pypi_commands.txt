###################################################################################################################
NOTE:
#####
This readme is only for "contributors" of the project.
You may use it as a guide in case you want to create variants of this tool on another PyPI or Test PyPI repository.
But then you need to change the name of your tool and create the corresponding projects.
###################################################################################################################

######################
for test in test.pypi:
######################

(inside folder where the setup.py file is in)

pip install -e .

python3 -m build

twine check dist/*

-------------------------------------------
type: ipradar2 (to test it locally first..)
-------------------------------------------

python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

      user: __token__
      pwd: (paste token here)

now copy the text from here:
https://test.pypi.org/project/ipradar2/0.0.3/

e.g.:
pip install -i https://test.pypi.org/simple/ ipradar2==0.0.3

and paste it on the machine you want to test the tool
(you may need to repeat if the first try fails!)

now the command ipradar2 is available for use


------------------------------------------------------------------------------

####################
for release in pypi:
####################

(inside folder where the setup.py file is in)

python3 setup.py sdist bdist_wheel

twine check dist/*

twine upload dist/*

enter user and password (or token)

now the pypi project is available here:
https://pypi.org/project/ipradar2

install on the machine you want to use the tool with:
pip install ipradar2

check version with:
pip show ipradar2

now the command ipradar2 is available for use
