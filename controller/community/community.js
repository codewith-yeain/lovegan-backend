import Comment from "../../models/comment_schema.js";
import Post from "../../models/post_schema.js"
import User from "../../models/user_schema.js"
import Scrap from "../../models/scrap_schema.js"

// 게시글 조회
const getPost = async (req, res) => {

    try {
        const posts = await Post.find()
        .populate('author')
        .lean()
        console.log(posts)

        res.status(200).json(posts);

    } catch(error) {
        res.status(500).json({ message : "게시글 조회 실패", error});
    }
};

// 각 게시글 조회
const getPostById = async (req, res) => {
    
    try {
        const { id } = req.params;
        console.log(req.params);

        const posts = await Post.findById(id)
        .populate('author')
        .lean()
        console.log(posts)

        if(!posts) return res.status(404).json({ message : "게시글을 찾을 수 없습니다." });

        res.status(200).json(posts);
    } catch (error) {
        res.status(500).json({ message : "게시글 상세 조회 실패", error});
    }
};

// 게시글 상세 페이지 조회
// const getPostDetailById = async (req, res) => {
//     try {

//         const { postId } = req.params;
//         console.log(req.params);
        
//         const postDetails = await postDetail.find(postId).lean();
//         console.log(postDetails)

//         if(!postDetails) return res.status(404).json({ message : "게시글 상세 페이지를 찾을 수 없습니다." });

//         res.status(200).json(postDetails);

//     } catch (error) {
//         res.status(500).json({ message : "게시글 상세 페이지 조회 실패", error});
//     }
// };

// 댓글
// 댓글 조회
const getComment = async (req, res) => {
    try {
        const comments = await Comment.find()
        .populate('post')
        .populate('user', 'id email nickname intro')
        .populate({
            path: 'replies',
            // populate: { path: 'user', select: 'nickname' }
        })
        .lean()
        const commentCount = comments.length;
        console.log(comments)
        // console.log(commentCount);

        res.status(200).json({comments, commentCount});
    } catch (error) {
        res.status(500).json({ message : "댓글 조회 실패", error});
    }
};

// 댓글 추가
const addComment = async (req, res) => {
    try {
        const {content, postId, userId} = req.body;
        console.log(req.body)
        
        if (!content || !postId || !userId) {
            return res.status(400).json({ message: "내용은 필수입니다." });
        }

        const addNewComment = new Comment({
            content,
            user : userId,
            post : postId,
            createAt: new Date(),
            updatedAt: new Date(),
        });

        await addNewComment.save();

        console.log("저장 완료: ", addNewComment)

        if(!addNewComment) {
            return res.status(500).json({ message : "댓글 저장 후 가져오는데 실패함."});
        }

        // 성공 응답
        return res.status(201).json({
            addCommentSuccess: true,
            message: "댓글이 성공적으로 등록되었습니다.",
            newComment: addNewComment
        });

    } catch (error) {
        console.error("서버 오류 :", error);
        res.status(500).json({ message : "댓글 저장 실패", error });
    }
};
 
// 대댓글 조회
// const getApply = async (req, res) => {
//     try {
//         const apply = await Comment.find();
//         console.log(apply)

//         res.status(404).json({ message : "대댓글 조회" });
//     } catch (error) {
//         res.status(500).json({ message : "대댓글 조회 실패", error});
//     }
// }

// 대댓글 추가
const addReply = async (req, res) => {
    try {
        console.log(req.body); // 불러와짐
        const { parentCommentId, userId, content } = req.body;
        
        if (!parentCommentId || !userId || !content) {
            return res.status(400).json({ message: "부모id, 유저id, content 필드를 찾을 수 없습니다." });
        }

        const comment = await Comment.findById(content);
        if (!comment) {
            return res.status(404).json({ message: "댓글을 찾을 수 없습니다." });
        }

        const newReply = {
            user: userId,
            content: content,   
            createAt: new Date(),
        };
        
        comment.replies.push(newReply); // 기존 댓글에 대댓글 추가
        await comment.save();
        

        return res.status(201).json({
            success: true,
            message: "대댓글이 성공적으로 추가되었습니다.",
            reply: newReply
        });

    } catch (error) {
        return res.status(500).json({ message: "대댓글 저장 실패", error });
    }
    // try {
    //     const { commentId, userId, content } = req.body;
    //     // console.log(req.body);
        
    //     if(!commentId || !userId || !content) {
    //         return res.status(200).json({ message : "부모id, 유저id, content 필드를 찾을 수 없습니다." })
    //     }
        
    //     // const parentComment = await Comment.findById(commentId)
    //     // .populate('user', 'nickname')
    //     // .populate({
    //     //     path: 'replies',
    //     //     populate: { path : 'replies', select : 'nickname'}
    //     // })

    //     // if (!parentComment) {
    //     //     return res.status(404).json({ message: "부모 댓글을 찾을 수 없습니다." });
    //     // }

    //     const comment = await Comment.findById(commentId);
    //     if (!comment) {
    //         return res.status(404).json({ message: "댓글을 찾을 수 없습니다." });
    //     }

    //     const newReply = new Comment({
    //         user: userId,
    //         // post: parentComment.post, // 원래 게시글 ID 유지
    //         content,
    //         createAt: new Date()
    //     });

    //     comment.replies.push(newReply);
    //     await comment.save();

    //     // 저장 후 부모 댓글의 `replies` 배열에 추가
    //     // const savedReply = await newReply.save();

    //     // console.log("부모 댓글의 replies 배열 :", parentComment.replies);
    //     // parentComment.replies.push(savedReply._id);
    //     // await parentComment.save();

    //     return res.status(201).json({
    //         success: true,
    //         message: "대댓글이 성공적으로 추가되었습니다.",
    //         reply: newReply
    //     });

    // } catch (error) {
    //     res.status(500).json({ message : "대댓글 저장 실패", error });
    // }
};

// 게시글 조회
const getMyPosts = async (req, res) => {
    try {
        // console.log(req.body);
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: '이메일이 필요합니다.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
        }

        // console.log(user._id);
        const myPosts = await Post.find({ author: user._id });

        // console.log("게시글 개수: " + myPosts.length);

        if (myPosts.length === 0) {
            return res.status(200).json({
                success: true,
                message: '작성한 게시물이 없습니다.',
                myPosts: [],
            });
        }

        return res.status(200).json({
            success: true,
            myPosts,
        });

    } catch (error) {
        console.error('Error fetching posts:', error);
        return res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
};

// 내가 스크랩한 게시글 조회
const getMyScraps = async (req, res) => {
    try {
        // console.log(req.body);
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: '이메일이 필요합니다.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
        }

        // postId를 변환하면서, postId 내부의 author도 변환
        const userScraps = await Scrap.find({ userId: user._id })
            .populate({
                path: "postId",
                populate: { path: "author", model: "User", select: "nickname email" }, //  model: "User" 명시
            })
            .exec();

        // postId가 실제 Post 객체로 변환됨
        const myScraps = userScraps.map(scrap => scrap.postId); 

        if (myScraps.length === 0) {
            return res.status(200).json({
                success: true,
                message: '스크랩한 게시물이 없습니다.',
                myScraps: [],
            });
        }

        return res.status(200).json({
            success: true,
            myScraps,
        });

    } catch (error) {
        console.error('Error fetching scraps:', error);
        return res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
};

const scrapPost = (req, res) => {
    const { userId, postId } = req.body;

    if (!userId || !postId) {
        return res.status(400).json({ error: 'userId와 postId가 필요합니다.' });
    }

    // 스크랩 추가 로직 (예: 데이터베이스에 추가)
    // userScraps는 임시 데이터 구조
    if (!userScraps[userId]) {
        userScraps[userId] = [];
    }

    if (!userScraps[userId].includes(postId)) {
        userScraps[userId].push(postId);
        return res.status(200).json({ message: '스크랩이 추가되었습니다.' });
    } else {
        return res.status(400).json({ message: '이미 스크랩한 게시물입니다.' });
    }
};

const scrapDelete = (req, res) => {
    const { userId, postId } = req.body;

    if (!userId || !postId) {
        return res.status(400).json({ error: 'userId와 postId가 필요합니다.' });
    }

    // 스크랩 삭제 로직 (예: 데이터베이스에서 삭제)
    if (userScraps[userId] && userScraps[userId].includes(postId)) {
        userScraps[userId] = userScraps[userId].filter(id => id !== postId);
        return res.status(200).json({ message: '스크랩이 취소되었습니다.' });
    } else {
        return res.status(400).json({ message: '스크랩된 게시물이 아닙니다.' });
    }
};


export {getPost, getPostById, getComment, addComment, addReply, getMyPosts, getMyScraps, scrapPost, scrapDelete};