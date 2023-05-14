import json

from matplotlib import pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, mean_squared_error
from sklearn import tree


## Similar to Decision Tree
file = open('./data/devices_IA_clases.json')
train = json.load(file)
file = open('./data/devices_IA_predecir_v2.json')
test = json.load(file)
x_train = []
y_train = []
x_test = []
y_test = []

# Getting data to train
for i in train:
    if i['servicios'] != 0:
        x_train.append([i['servicios_inseguros']/i['servicios']])
    else:
        x_train.append([0])
    y_train.append(i['peligroso'])

# Getting data to test
for i in test:
    if i['servicios'] != 0:
        x_test.append([i['servicios_inseguros']/i['servicios']])
    else:
        x_test.append([0])
    y_test.append(i['peligroso'])

randomForest = RandomForestClassifier(max_depth=3, random_state=0, n_estimators=10)
randomForest.fit(x_train, y_train)
# Doing prediction
prediction = randomForest.predict(x_test)
hits = 0
fails = 0
## Just to check the model
for i in range(0, len(prediction)):
    if prediction[i] == y_test[i]:
        hits += 1
    else:
        fails += 1
print("HITS: " + str(hits) + "\nFAILS: " + str(fails) + "\nHIT PER FAIL: " + str(hits / fails))
for i in range(len(randomForest.estimators_)):
    tree.plot_tree(randomForest.estimators_[i], filled=True, feature_names=["servicios_inseguros/servicios"], fontsize=7,class_names=["no peligroso", "peligroso"])
    plt.show()