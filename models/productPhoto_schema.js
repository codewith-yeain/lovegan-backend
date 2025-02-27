import mongoose, { model, Schema } from "mongoose";

const productPhotoSchema = new Schema({
    product: {type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true},
    url: {type: String, required: true}
});

export default model("ProductPhoto", productPhotoSchema, "productPhoto");