const { Schema, model } = require('mongoose');

const ThreadBindingSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', index: true, required: true },
  assistant_id: { type: String, required: true },
  thread_id: { type: String, required: true, unique: true },
  title: { type: String, default: 'New chat' },
  archived: { type: Boolean, default: false },
  last_message_at: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
});

ThreadBindingSchema.index({ user: 1, archived: 1, last_message_at: -1 });

const ThreadBinding = model('ThreadBinding', ThreadBindingSchema);

module.exports = { ThreadBinding };
