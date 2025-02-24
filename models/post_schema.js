import { Schema, model } from "mongoose";
import { getCurrentTime } from "../utils/utils.js";

// 게시글 스키마
const postSchema = new Schema({
    author: { type: Schema.Types.ObjectId, ref : "User", required : true },
    title : { type : String, required : true}, // 게시글 제목
    content : { type : String, required : true },
    createdAt : { type : Date, default : getCurrentTime }, // 작성 날짜
    likeCount : { type : Number, default : 0, required : true },
    scrapCount : { type : Number, default : 0, required : true },
    viewCount : { type : Number, default : 0, required : true }
});

export default model("Post", postSchema, "post");