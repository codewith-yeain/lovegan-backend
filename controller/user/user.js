import User from "../../models/user_schema.js";
import path from 'path'
// import CoolsmsMessageService from "coolsms-node-sdk";
// import msgModule from 'coolsms-node-sdk';
import coolsms from 'coolsms-node-sdk';
import bcrypt from "bcrypt";


const loginUser = async (req, res) => {
    console.log("로그인 정보 : ", req.body)
    // const { email, password } = req.body;
    const findUser = await User.findOne({ email : req.body.email }).lean();
    // console.log(req.body)
    if(!findUser){
        return res.status(401).json({
            loginSuccess : false,
            message : "존재하지 않는 아이디 또는 비밀번호입니다."
        })
    } 
    try{
        const email = req.body.email;
        const password = req.body.password;
        const passwordMatch = await bcrypt.compare(password, findUser.password);
        if(!passwordMatch) {
            return res.status(401).json({
                loginSuccess: false,
                message: "존재하지 않는 아이디 또는 비밀번호입니다."
            });
        }
        const { password:_, ...user } = findUser;

        return res.status(200).json({
            user,
            loginSuccess: true,
            message: "로그인이 완료되었습니다."
        });
    }
    catch(error){
        console.error(error);
        return res.status(500).json({message : "서버 오류 발생"})
    }
}

const registerUser = async (req, res) => {
    // console.log(req.body)
    const { nickname, email, password, phone } = req.body;
    const findUser = await User.findOne({
        $or: [{ email: email }, { phone: phone }]
    }).lean();

    if(findUser){
        return res.status(409).json({
            registerSuccess : false,
            message : "이미 존재하는 계정입니다."
        })
    }else{
        // let register = {
        //     email : email,
        //     password : password,
        //     phone : phone,
        //     nickname : nickname
        // }
        // await User.create(register);
        // return res.status(201).json({
        //     registerSuccess : true,
        //     message : "축하합니다. 회원가입이 완료되었습니다."
        // })
        // 비밀번호 해시화
        const saltRounds = 10; // 해시 강도를 설정(높을 수록 안전);
        const plainPassword = req.body.password
        console.log("현재 비밀번호", plainPassword);

        bcrypt.hash(plainPassword, saltRounds, async (err, hashPassword) => {
            if(err){
                console.log(err)
            }else{
                console.log("해쉬 비밀번호", hashPassword);
                let registerUser = {
                    email : email,
                    password : hashPassword,
                    nickname : nickname,
                    phone : phone
                }

                await User.create(registerUser);
                return res.status(201).json({
                    message : "축하합니다. 회원가입이 완료되었습니다.",
                    registerSuccess : true
                })
            }
        })
    }
}
const updateUser = async (req, res) => {
    //req.body.email
    const findUser = await User.findOne({email : req.body.email })
    const updatedUser = await User.updateOne(findUser,{
        // email : req.body.email,
        // name : req.body.name
    })
}
const deleteUser = async (req, res) => {
    const user = await User.findOne({email : req.body.email});
    const DeletedUser = await User.deleteOne(user);
}

const updatePicture = async (req, res) => {
    const uploadFolder = "uploads/profiles";
    const relativePath = path.join(uploadFolder, req.file.filename).replace(/\\/g, '/');
    const email = req.body.email;

    const currentUser = await User.findOne({email : email})
    const updatedUser = await User.updateOne(
        currentUser,
        {picture : `/${relativePath}`})

    console.log(req.body)
    res.status(200).json({
        message : "Updated",
        filePath : `/${relativePath}`,
    })
}

const resetPW = async (req, res) => {
    console.log(req.body);
    const {newPW, confirmPW, phoneNumber} = req.body;
    try{
        const findUser = await User.findOne({phone : phoneNumber});
        if(!findUser){
            return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        }
        if(newPW !== confirmPW){
            return res.status(404).json({message : "비밀번호가 일치하지 않습니다."});
        }
        const passwordMatch = await bcrypt.compare(newPW, findUser.password);
        if(passwordMatch) {
            return res.status(401).json({
                message: "현재 비밀번호와 일치합니다."
            });
        }

        const saltRounds = 10;

        bcrypt.hash(newPW, saltRounds, async (err, hashPassword) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "비밀번호 해싱 오류 발생" });
            }

            console.log("해시된 비밀번호:", hashPassword);

            try {
                const result = await User.updateOne(
                    { phone: phoneNumber },
                    { $set: { password: hashPassword } }
                );

                if (result.modifiedCount === 0) {
                    return res.status(500).json({ message: "비밀번호 변경 실패" });
                }

                return res.status(200).json({ message: "비밀번호 변경 성공" });
            } 
            catch (error) {
                console.error(error);
                return res.status(500).json({ message: "서버 오류 발생" });
            }
        })
    }
    catch(error){
        console.error(error);
        return res.status(500).json({ message: "서버 오류 발생" });
    }
};

const updatePassword = async (req, res) => { 
    try {
        // 사용자 찾기
        const { email, currentPassword, newPassword } = req.body;
        
        const findUser = await User.findOne({ email: email });
        
        if (!findUser) {
            return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        }

        // // ✅ 현재 비밀번호 일치 여부 확인
        // if (findUser.password !== currentPassword) {
        //     return res.status(401).json({ message: "현재 비밀번호가 일치하지 않습니다." });
        // }

        // 현재 비밀번호 해시 비교 (bcrypt.compare 사용)
        const isMatch = await bcrypt.compare(currentPassword, findUser.password);
        if (!isMatch) {
            return res.status(401).json({ message: "현재 비밀번호가 일치하지 않습니다." });
        }

        // 새 비밀번호 해싱
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // 비밀번호 업데이트 (해싱된 비밀번호 사용)
        const result = await User.updateOne(
            { email }, 
            { $set: { password: hashedPassword } }
        );

        if (result.modifiedCount === 0) {
            return res.status(500).json({ message: "비밀번호 변경 실패" });
        }

        return res.status(200).json({ message: "비밀번호 변경 성공" });
    } catch (error) {
        console.error("비밀번호 변경 중 오류:", error);
        res.status(500).json({ message: "서버 오류" });
    }
}

const updateNickname = async (req, res) => { 
    try {
        // 사용자 찾기
        const { email, value } = req.body;
        
        const findUser = await User.findOne({ email: email });
        console.log("updateNickname" + updateNickname);
        
        if (!findUser) {
            return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        }

        await User.updateOne(
            { email: email },  // 검색 조건 수정
            { $set: { nickname: value } } // $set 사용
        );

        res.status(200).json({ message: "닉네임 변경 성공" });
    } catch (error) {
        console.error("닉네임 변경 중 오류:", error);
        res.status(500).json({ message: "서버 오류" });
    }
}

const updateIntro = async (req, res) => { 
    try {
        // 사용자 찾기
        const { email, value } = req.body;
        
        const findUser = await User.findOne({ email: email });
        
        if (!findUser) {
            return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        }

        await User.updateOne(
            { email: email },  // 검색 조건 수정
            { $set: { intro: value } } // $set 사용
        );

        res.status(200).json({ message: "한 줄 소개 변경 성공" });
    } catch (error) {
        console.error("한 줄 소개 변경 중 오류:", error);
        res.status(500).json({ message: "서버 오류" });
    }
}


// 인증을 위해 발급받은 본인의 API Key와 API Secret을 사용
const sms = coolsms.default;
const apiKey = 'NCS6DDSBDYN6FDFS';
const apiSecret = 'OYHFVIXYADK5MORXSKROG47EN1YGNQA2';
const messageService = new sms(apiKey, apiSecret);

const verificationCodes = {}; // 저장소

const generateVerificationCode = (phoneNumber) => {
    const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6자리 코드
    verificationCodes[phoneNumber] = {
        code: code,
        expiresAt: Date.now() + 3 * 60 * 1000 // 3분 후 만료
    };
    return code;
};

/**
 * 휴대폰 번호로 인증 코드 전송
 */
const sendVerificationCode = async (req, res) => {
    const { phoneNumber, email } = req.body;
    console.log(req.body);
    if (!phoneNumber) {
        return res.status(400).json({ success: false, message: "휴대폰 번호를 제공해야 합니다.", email : req.body.email });
    }

    try {
        // 인증 코드 생성 및 저장
        const verificationCode = generateVerificationCode(phoneNumber);
        console.log("인증번호 저장 : ", verificationCode)

        // 메시지 구성
        const message = {
            text: `[인증번호] 인증번호: ${verificationCode}`,
            to: phoneNumber,
            from: '01093400031'
        };

        console.log("message" + message);

        // 인증번호를 메모리에 저장 (실제 환경에서는 DB에 저장 권장)
        verificationCodes[phoneNumber] = verificationCode;

        // 문자 전송
        await messageService.sendOne(message);
        res.status(200).json({ success: true, message: "인증번호가 전송되었습니다.", email: req.body.email });
    } catch (error) {
        console.error("문자 전송 오류:", error);
        res.status(500).json({ success: false, message: "문자 전송에 실패했습니다." });
    }
};

/**
 * 인증 코드 검증
 */
const verifyCode = async (req, res) => {
    const { email, phoneNumber, code } = req.body;

    console.log("verifyCode 함수: " + email);
    console.log("verifyCode 함수: " + phoneNumber);
    console.log("verifyCode 함수: " + code);

    const findUser = await User.findOne({ email: email });
        
    if (!findUser) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    if (!phoneNumber || !code) {
        return res.status(400).json({ success: false, message: "휴대폰 번호와 인증 코드를 제공해야 합니다." });
    }

    try {
        const storedData = verificationCodes[phoneNumber];
        console.log("storedData: " + storedData);

        if (!storedData) {
            return res.status(400).json({ success: false, message: "인증 코드가 존재하지 않습니다." });
        }

        // 만료 시간 검사
        // if (Date.now() > storedData.expiresAt) {
        //     // delete verificationCodes[phoneNumber];
        //     return res.status(400).json({ success: false, message: "인증 코드가 만료되었습니다." });
        // }

        

        // 저장된 인증 코드와 비교
        if (storedData === code) {
            // 인증 성공
            // 휴대폰 번호 업데이트 (updateOne 수정)
            await User.updateOne(
                { email: email },  // 검색 조건 수정
                { $set: { phone: phoneNumber } } // $set 사용
            );
            delete verificationCodes[phoneNumber]; // 인증 완료 후 코드 삭제
            res.status(200).json({ success: true, message: "인증에 성공하여 전화번호가 변경되었습니다." });
        } else {
            res.status(400).json({ success: false, message: "인증 코드가 올바르지 않습니다." });
        }
    } catch (error) {
        console.error("인증 코드 확인 오류:", error);
        res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
};
// 회원가입할 때 인증번호 인증
const signupVerifyCode = async (req, res) => {
    console.log("요청받은 데이터 : ", req.body)
    const { phoneNumber, code } = req.body;
    console.log("verifyCode 함수: " + phoneNumber);
    console.log("verifyCode 함수: " + code);

    if (!phoneNumber || !code) {
        return res.status(400).json({ success: false, message: "휴대폰 번호와 인증 코드를 제공해야 합니다." });
    }

    try {
        const storedData = verificationCodes[phoneNumber];
        console.log("저장된 인증번호:", storedData);

        if (!storedData) {
            return res.status(400).json({ success: false, message: "인증 코드가 존재하지 않습니다." });
        }

        if (String(storedData).trim() !== String(code).trim()) {
            return res.status(400).json({ success: false, message: "인증 코드가 올바르지 않습니다." });
        }

        // 인증 완료 후 코드 삭제
        delete verificationCodes[phoneNumber];

        return res.status(200).json({ success: true, message: "인증 성공!" });

    } catch (error) {
        console.error("인증 코드 확인 오류:", error);
        return res.status(500).json({ success: false, message: "서버 오류 발생" });
    }
}

const findPhoneNumber = async (req, res) => {
    console.log("아이디찾기 데이터 : ", req.body);
    const user = await User.findOne({phone : req.body.phoneNumber});
    console.log(user.email)
    if(!user){
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    else{
        return res.status(200).json({success : true, message : "아이디 찾기 성공", email : user.email})
    }
}

// 내 팔로잉 조회
const getMyFollowing = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: '이메일이 필요합니다.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
        }

        let myFollowing = [];

        if (user.following.length === 0) {
            return res.status(200).json({
                success: true,
                message: '팔로잉이 없습니다.',
                myFollowing: [],
            });
        }

        for (let i = 0; i < user.following.length; i++) {
            let followingUser = await User.findOne({ _id: user.following[i]._id });
            myFollowing.push(followingUser);
        }

        return res.status(200).json({
            success: true,
            myFollowing,
        });

    } catch (error) {
        console.error('Error fetching following:', error);
        return res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
};


// 내 팔로잉 조회
const getMyFollowers = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: '이메일이 필요합니다.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
        }

        let myFollowers = [];

        if (user.followers.length === 0) {
            return res.status(200).json({
                success: true,
                message: '팔로워가 없습니다.',
                myFollowers: [],
            });
        }

        for (let i = 0; i < user.followers.length; i++) {
            let followerUser = await User.findOne({ _id: user.followers[i]._id });
            myFollowers.push(followerUser);
        }

        return res.status(200).json({
            success: true,
            myFollowers,
        });

    } catch (error) {
        console.error('Error fetching followers:', error);
        return res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
};

// 팔로우 상태 조회
const followStatus = async (req, res) => {
    try {
        const { userId, targetUserId } = req.body;

        if (!userId || !targetUserId) {
            return res.status(400).json({ success: false, message: "userId와 targetUserId가 필요합니다." });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "사용자를 찾을 수 없습니다." });
        }

        const isFollowing = user.following.includes(targetUserId);
        res.json({ success: true, isFollowing });

    } catch (error) {
        console.error('팔로우 상태 확인 중 오류 발생:', error);
        res.status(500).json({ success: false, message: "서버 오류 발생" });
    }
}

const toggleFollow = async (req, res) => {
    try {
        const { userId, targetUserId } = req.body;

        if (!userId || !targetUserId) {
            return res.status(400).json({ success: false, message: "userId와 targetUserId가 필요합니다." });
        }

        const user = await User.findById(userId);
        const targetUser = await User.findById(targetUserId);

        if (!user || !targetUser) {
            return res.status(404).json({ success: false, message: "사용자를 찾을 수 없습니다." });
        }

        const isFollowing = user.following.includes(targetUserId);

        if (isFollowing) {
            // 언팔로우 (리스트에서 제거)
            user.following = user.following.filter(id => id != targetUserId);
            targetUser.followers = targetUser.followers.filter(id => id != userId);
            if (user.followingCount != 0){
                user.followingCount -= 1;
            }
            if (targetUser.followerCount != 0){
                targetUser.followerCount -= 1;
            }
        } else {
            // 팔로우 (리스트에 추가)
            user.following.push(targetUserId);
            targetUser.followers.push(userId);
            user.followingCount += 1;
            targetUser.followerCount += 1;
        }

        await user.save();
        await targetUser.save();

        res.json({ success: true, isFollowing: !isFollowing });

    } catch (error) {
        console.error('팔로우 토글 중 오류 발생:', error);
        res.status(500).json({ success: false, message: "서버 오류 발생" });
    }
}

export {loginUser, registerUser, updateUser, deleteUser, updatePicture, updatePassword, updateNickname, updateIntro, sendVerificationCode, verifyCode, getMyFollowing, getMyFollowers, followStatus, toggleFollow, signupVerifyCode, findPhoneNumber, resetPW }

