import shlex,  subprocess

# NOTE:
# Use pip freeze when you want to rebuild the same environment, e.g.:
#   pip freeze > requirements_venv_as4pgc.txt
# Use pipreqs when you want to document only direct dependencies from your code.
print("Updating requirements.txt..")
p1 = subprocess.Popen(shlex.split("pipreqs --force ./ --ignore backups"), shell=True)
p1.wait()
