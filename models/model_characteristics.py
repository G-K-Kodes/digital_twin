import joblib
from sklearn.tree import export_text

model_2 = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_payload.pkl')
label_mapping_2 = joblib.load('C:/Users/gokul/digital_twin/models/label_mapping_payload.pkl')

print(label_mapping_2)
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
'''import matplotlib.pyplot as plt
import seaborn as sns

# Feature names
feature_names = ['srcip', 'sport', 'dstip', 'dsport', 'protocol_m', 
                 'sttl', 'total_len', 'payload', 'Timestamp']
importances = [0.1340799, 0.09127316, 0.12455794, 0.15035652, 0.02905973,
               0.01775667, 0.14380257, 0.14830705, 0.16080647]

# Plot
sns.set(style="whitegrid")
plt.figure(figsize=(10, 6))
sns.barplot(x=importances, y=feature_names, palette="Blues_d")
plt.title("Random Forest Feature Importances")
plt.xlabel("Importance Score")
plt.ylabel("Feature")
plt.tight_layout()
plt.show()'''

'''from sklearn.tree import plot_tree
import matplotlib.pyplot as plt

feature_names = ['srcip', 'sport', 'dstip', 'dsport', 'protocol_m', 
                 'sttl', 'total_len', 'payload', 'Timestamp']

plt.figure(figsize=(20, 10))
plot_tree(model_2.estimators_[0], 
          feature_names=feature_names, 
          class_names=[str(c) for c in model_2.classes_],
          filled=True, 
          rounded=True, 
          max_depth=1)  # Keep it shallow for readability
plt.title("Random Forest Sample Tree (Depth 1)")
plt.show()'''

'''from sklearn.tree import export_graphviz
from graphviz import Source
import os

# Create output directory if it doesn't exist
os.makedirs("rf_trees", exist_ok=True)

feature_names = ['srcip', 'sport', 'dstip', 'dsport', 'protocol_m', 
                 'sttl', 'total_len', 'payload', 'Timestamp']

# Loop through all estimators (trees)
for idx, estimator in enumerate(model_2.estimators_):
    dot_data = export_graphviz(
        estimator,
        out_file=None,
        feature_names=feature_names,  # Make sure this is a list of your feature names
        class_names=model_2.classes_.astype(str),  # If target is numeric
        rounded=True,
        proportion=False,
        precision=2,
        filled=True
    )
    graph = Source(dot_data)
    output_path = f"rf_trees/tree_{idx}"
    graph.render(output_path, format="png", cleanup=True)'''

'''from fpdf import FPDF

pdf = FPDF()
for i in range(100):  # or all trees
    pdf.add_page()
    pdf.image(f'rf_trees/tree_{i}.png', x=10, y=10, w=180)
    pdf.set_font("Arial", size=12)
    pdf.ln(190)
    pdf.cell(200, 10, txt=f"Tree {i}", ln=True, align='C')

pdf.output("rf_all_trees.pdf")'''