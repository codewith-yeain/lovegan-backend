import { Schema, model } from "mongoose";
import { getCurrentTime } from "../utils/utils.js";

const scrapSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },  // 스크랩한 사용자
    postId: { type: Schema.Types.ObjectId, ref: "Post", required: true },  // 스크랩한 게시물
    createdAt: { type: String, default: getCurrentTime }  // 스크랩한 시간
});

export default model("Scrap", scrapSchema, "scraps");

