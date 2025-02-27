import express from "express";
import { addComment, addReply, getComment, getMyPosts, getMyScraps, getPost, getPostById, scrapDelete, scrapPost } from "../../controller/community/community.js";

const communityRouter = express.Router();

// 게시물 생성
// communityRouter.post("/createPost", createPost);

// 게시물 가져오기
communityRouter.get("/getPost", getPost);

// 특정 게시물 가져오기 => 게시물을 클릭 했을 때 어떤 게시물인지 구분이 가능하도록 만들어보기
communityRouter.get("/getPostById/:id", getPostById);

// 게시물 상세 페이지 데이터 조회
// communityRouter.get("/getPostDetailById/:id", getPostDetailById);

// 댓글 가져오기 -> 특정 게시물의 댓글들 / 몽고디비에 있는 댓글들 불러오기
communityRouter.get("/getComment/:id", getComment);

// 댓글 추가하기 -> 몽고디비에 저장
communityRouter.post("/addComment", addComment);

// 대댓글 조회하기
// communityRouter.get("/getApply", getApply);

// 대댓글 추가하기 -> 특정 댓글들에 대댓글 달기(몽고디비에 추가, 저장 될 수 있도록)
communityRouter.post("/addReply", addReply);

// 내 게시물 가져오기
communityRouter.post("/getMyPosts", getMyPosts);

// 내가 스크랩한 게시물 가져오기
communityRouter.post("/getMyScraps", getMyScraps);

// 게시물 스크랩 추가하기/삭제하기
communityRouter.post("/scrap", scrapPost);
communityRouter.post("/scrap", scrapDelete);

export default communityRouter;