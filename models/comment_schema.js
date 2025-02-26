import { model, Schema } from "mongoose";
import { getCurrentTime } from "../utils/utils.js";

const commentSchema = new Schema({
    user : {type : Schema.Types.ObjectId, ref : "User", required : true, default: "익명"},
    post: { type: Schema.Types.ObjectId, ref: 'Post', required: true }, // postId 저장
    content : { type : String, required : true }, // 댓글 내용
    replies: [
        { 
            user: { type: Schema.Types.ObjectId, ref: "User", required: true },
            content: { type: String, required: true },
            createAt: { type: Date, default: Date.now },
        }
    ], 
    createAt : { type : Date, default : getCurrentTime }, 
    updateAt : { type : Date, default : getCurrentTime },
});

export default model("Comment", commentSchema, "comment")