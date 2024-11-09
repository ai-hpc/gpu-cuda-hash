import numpy as np
from sklearn.linear_model import LinearRegression

# Load indices from the file
def load_indices(file_path):
    with open(file_path, 'r') as file:
        indices = [int(line.strip()) for line in file]
    return np.array(indices)

# Load data
indices = load_indices('h-myresult_indices.txt')

# Calculate split sizes
train_size = int(0.7 * len(indices))
validation_size = int(0.15 * len(indices))
test_size = len(indices) - train_size - validation_size

# Split data into training, validation, and test sets
train_indices = indices[:train_size]
validation_indices = indices[train_size:train_size + validation_size]
test_indices = indices[train_size + validation_size:]

# Prepare features and labels
X_train = train_indices.reshape(-1, 1)
y_train = train_indices

X_validation = validation_indices.reshape(-1, 1)
y_validation = validation_indices

X_test = test_indices.reshape(-1, 1)
y_test = test_indices.reshape(-1, 1)

# Train a simple linear regression model
model = LinearRegression()
model.fit(X_train, y_train)

# Predict on the test set
test_predictions = model.predict(y_test)

# Convert predictions to integers
test_predictions = test_predictions.astype(int)

# Combine indices up to the test set with the predicted values
combined_indices = np.concatenate((indices[:train_size + validation_size], test_predictions))

# Output the combined indices to a file
with open('ai-result.txt', 'w') as outfile:
    for index in combined_indices:
        outfile.write(f"{index}\n")
