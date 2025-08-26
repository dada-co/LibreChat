const { Schema, model } = require('mongoose');

const AssistantBindingSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', index: true, unique: true, required: true },
  assistant_id: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const AssistantBinding = model('AssistantBinding', AssistantBindingSchema);

module.exports = { AssistantBinding };
