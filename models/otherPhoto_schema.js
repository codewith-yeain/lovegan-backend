import mongoose, { model, Schema } from "mongoose";

const otherPhotoSchema = new Schema({
    other: {type: mongoose.Schema.Types.ObjectId, ref: "Other", required: true},
    url: {type: String, required: true}
});

export default model("OtherPhoto", otherPhotoSchema, "otherPhoto");