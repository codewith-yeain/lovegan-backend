// package.json type : module 추가 
// dbname : project 이름으로 변경
// 1. db : DBMS 연결 및 설정
// 2. app.js(server.js) : 서버 설정, 미들웨어 설정 및 라우팅 설정
// 3. schemas : 데이터에 맞는 스키마 구성 (models 폴더 안에)
// 4. controller : DB에 접근하는 비즈니스 로직 작성
// 5. routers : 요청한 경로에 맞는 controller로 실행하기 위한 라우터 작성
// 6. utils : 중복 코드를 하나의 유틸 함수로 묶거나 외부 라이브러리들
// 7. auth : 인증, 인가 (OAuth, JWT, local)

// 설치한 라이브러리 모듈 가져오기
import connect from './connect/connect.js';
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';


// 4.16버전 이상 내장
import bodyParser from 'body-parser';
import rootRouter from './routes/rootRouter.js';

// passport
import passport from 'passport';
import { initializePassport } from './auth/auth.js';

// 이미지 등록
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url'
// ES Modules에서 __dirname을 인식할 수 있도록 변경
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename)


// sns 로그인시 session이 필요할 수 있음, JWT를 생성해서 보낼 수 있다.
import session from 'express-session';

connect(); // mongoDB 연결
dotenv.config() // 환경변수 설정

const port = 8000;
const app = express();

// .use()는 미들웨어
// 어떤 요청이든 지정된 로직보다 먼저 작업한다. 즉 전처리이다.
app.use(bodyParser.json());

// CORS 전체 허용
// CORS 테스트용 서버에서 모두 허용
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*")
  next()
})

// extended true면 qs모듈을 사용하여 쿼리스트링으로 인식
app.use(express.urlencoded({extended : false}));
app.use(cors({
  origin : "http://localhost:3000",
  method : ['GET', 'POST', 'DELETE', 'PUT'],
  credentials : true,
}))

// passport 미들웨어 등록
app.use(passport.initialize());

// passport 로직
initializePassport()

// 이미지 등록 로직
const uploadFolder = "uploads/profiles"

const getUniqueFileName = (originalName, uploadFolder) => {
  const ext = path.extname(originalName); // 확장자를 추출 // .jpg
  const baseName = path.basename(originalName, ext) // 확장자를 제외하고 나머지를 추출 // 파일명
  let uniqueName = originalName;
  let counter = 1;

  while(fs.existsSync(path.join(uploadFolder, uniqueName))){
    uniqueName = `${baseName}(${counter})${ext}`;
    counter++
  }
  return uniqueName;
}

const upload = multer({
  storage : multer.diskStorage({
    destination(req, file, done){
      done(null, path.join(__dirname, "./uploads/profiles")) // 프로필 이미지 저장 경로 설정
    },
    filename(req, file, done){
      const uniqueFileName = getUniqueFileName(file.originalname, uploadFolder); // 파일이름 지정
      done(null, uniqueFileName)
    }
  })
})

const uploadMiddleware = upload.single("picture");
// 정적 파일 제공(서버의 uploads 폴더를 공개)
// "/uploads" 경로로 요청하면 요청이 실제 파일 시스템 uploads 디렉토리와 연결
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(uploadMiddleware);

// session 설명 
app.use(session(
  {
    secret : "SECRET_KEY",
    resave : false,
    saveUninitialized : true
  }
))
app.use(passport.session())
// passport로 인증된 유저를 session에 등록해주는 메서드
passport.serializeUser((user, done) => {
  done(null, user)
})
// passport로 인증된 유저를 session에서 제거해주는 메서드
passport.deserializeUser((user, done) => {
  done(null, user)
})


app.use("/", rootRouter);
app.listen(port, () => {
  console.log("express 서버 실행!")
})


