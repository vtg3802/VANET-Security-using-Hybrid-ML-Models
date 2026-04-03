.ONESHELL:
SHELL := /bin/bash

setup_env:
	python3 -m venv myenv
	source myenv/bin/activate
	pip3 install pandas scikit-learn numpy matplotlib seaborn scipy joblib tqdm python-dateutil

run_SVM:
	source myenv/bin/activate
	python3 ML_Models/SVM_Model.py

run_RandomForest:
	source myenv/bin/activate
	python3 ML_Models/RandomForest_Model.py

run_KNN:
	source myenv/bin/activate
	python3 ML_Models/KNN_Model.py

run_LogicRegression:
	source myenv/bin/activate
	python3 ML_Models/LogisticRegression_Model.py

run_MLP:
	source myenv/bin/activate
	python3 ML_Models/MLP_Model.py