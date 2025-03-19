import joblib
from sklearn.tree import export_text


model = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_netflow.pkl')
#Model parameters
print(model.get_params())
#Feature importance
print(model.feature_importances_)
#Number of decision tree estimators
print(model.n_estimators)
#Maximum depth of each generated tree
print(model.max_depth)
#The generated decision tree
print(export_text(model.estimators_[0]))

model_2 = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_payload.pkl')
#Model parameters
print(model_2.get_params())
#Feature importance
print(model_2.feature_importances_)
#Number of decision tree estimators
print(model_2.n_estimators)
#Maximum depth of each generated tree
print(model_2.max_depth)
#The generated decision tree
print(export_text(model_2.estimators_[0]))