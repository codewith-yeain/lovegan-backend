import connect from "../connect/connect.js";
import Product from '../models/product_schema.js';
import Other from '../models/other_schema.js'
import User from "../models/user_schema.js";
import ProductPhoto from "../models/productPhoto_schema.js";

connect();

// await Product.create(
//     // { title: "아보카도", description: "유기농 아보카도 3개입", price: 8700, star: "4.9", review: 678, discount: 25, tag: "BEST", categories: "채소" },
//     { title: "바나나", description: "신선한 바나나 5개입", price: 4500, star: "4.8", review: 1205, discount: 15, tag: "NEW", categories: "과일" },
//     { title: "키위", description: "달콤한 키위 6개입", price: 5500, star: "4.7", review: 987, discount: 10, tag: "SALE", categories: "과일" },
//     { title: "사과", description: "유기농 사과 6개입", price: 6800, star: "4.9", review: 1543, discount: 20, tag: "BEST", categories: "과일" },
//     { title: "배", description: "신선한 배 4개입", price: 7800, star: "4.6", review: 465, discount: 12, tag: "NEW", categories: "과일" },
//     { title: "토마토", description: "신선한 토마토 500g", price: 3200, star: "4.8", review: 234, discount: 5, tag: "SALE", categories: "채소" },
//     { title: "당근", description: "신선한 당근 1kg", price: 3900, star: "4.7", review: 212, discount: 8, tag: "BEST", categories: "채소" },
//     { title: "시금치", description: "유기농 시금치 300g", price: 3200, star: "4.8", review: 421, discount: 10, tag: "NEW", categories: "채소" },
//     { title: "오이", description: "신선한 오이 3개입", price: 2500, star: "4.5", review: 532, discount: 15, tag: "BEST", categories: "채소" },
//     { title: "파프리카", description: "파프리카 3개입", price: 3800, star: "4.6", review: 312, discount: 10, tag: "BEST", categories: "채소" },
//     { title: "레몬", description: "신선한 레몬 4개입", price: 4800, star: "4.7", review: 654, discount: 5, tag: "NEW", categories: "과일" },
//     { title: "귤", description: "달콤한 귤 10개입", price: 6200, star: "4.8", review: 908, discount: 18, tag: "SALE", categories: "과일" },
//     { title: "망고", description: "신선한 망고 2개입", price: 9500, star: "4.9", review: 345, discount: 20, tag: "BEST", categories: "과일" },
//     { title: "포도", description: "신선한 포도 500g", price: 5300, star: "4.7", review: 765, discount: 12, tag: "NEW", categories: "과일" },
//     { title: "딸기", description: "신선한 딸기 300g", price: 7500, star: "4.9", review: 980, discount: 5, tag: "SALE", categories: "과일" },
//     { title: "오렌지", description: "신선한 오렌지 6개입", price: 5900, star: "4.8", review: 400, discount: 8, tag: "BEST", categories: "과일" },
//     { title: "청포도", description: "청포도 500g", price: 6800, star: "4.8", review: 342, discount: 15, tag: "NEW", categories: "과일" },
//     { title: "감자", description: "유기농 감자 1kg", price: 2800, star: "4.5", review: 212, discount: 10, tag: "BEST", categories: "채소" },
//     { title: "양배추", description: "신선한 양배추 1kg", price: 3300, star: "4.6", review: 120, discount: 5, tag: "BEST", categories: "채소" },
//     { title: "배추", description: "신선한 배추 1개", price: 4500, star: "4.7", review: 678, discount: 12, tag: "NEW", categories: "채소" },
//     { title: "비건 닭가슴살", description: "식물성 단백질로 만든 비건 닭가슴살 500g", price: 9800, star: "4.9", review: 350, discount: 15, tag: "NEW", categories: "고기대용" },
//     { title: "두부 스테이크", description: "두부로 만든 고기 대체 스테이크 4개입", price: 6200, star: "4.8", review: 240, discount: 10, tag: "BEST", categories: "고기대용" },
//     { title: "렌틸콩 버거", description: "고단백 렌틸콩으로 만든 버거 패티 6개입", price: 7500, star: "4.7", review: 512, discount: 5, tag: "NEW", categories: "고기대용" },
//     { title: "불고기 맛 양배추", description: "불고기 양념을 입힌 양배추 500g", price: 3200, star: "4.6", review: 312, discount: 8, tag: "SALE", categories: "채식반찬" },
//     { title: "고구마 조림", description: "달콤한 고구마 조림 300g", price: 2800, star: "4.9", review: 450, discount: 12, tag: "NEW", categories: "채식반찬" },
//     { title: "시금치 된장국", description: "신선한 시금치와 된장으로 만든 전통적인 된장국", price: 3300, star: "4.8", review: 580, discount: 10, tag: "BEST", categories: "채식반찬" },
//     { title: "고추장 멸치볶음", description: "매콤한 고추장 양념 멸치볶음 200g", price: 4500, star: "4.7", review: 312, discount: 15, tag: "SALE", categories: "채식반찬" },
//     { title: "김치전", description: "바삭하게 구운 김치전 5개입", price: 5200, star: "4.9", review: 756, discount: 8, tag: "BEST", categories: "채식반찬" },
//     { title: "쌀국수", description: "향긋한 고수와 함께 즐기는 쌀국수", price: 6800, star: "4.8", review: 430, discount: 10, tag: "NEW", categories: "간편식" },
//     { title: "라면", description: "매운 라면 5개입", price: 3500, star: "4.7", review: 890, discount: 15, tag: "SALE", categories: "간편식" },
//     { title: "간편 볶음밥", description: "30초 만에 완성되는 간편 볶음밥", price: 2900, star: "4.6", review: 660, discount: 10, tag: "NEW", categories: "간편식" },
//     { title: "치킨너겟", description: "바삭하고 고소한 치킨너겟 10개입", price: 6500, star: "4.9", review: 320, discount: 20, tag: "SALE", categories: "간식과일견과" },
//     { title: "허니머스타드 너겟", description: "달콤한 허니머스타드 양념을 입힌 너겟", price: 6800, star: "4.8", review: 780, discount: 10, tag: "BEST", categories: "간식과일견과" },
//     { title: "아몬드", description: "건강한 아몬드 200g", price: 5500, star: "4.7", review: 600, discount: 12, tag: "NEW", categories: "간식과일견과" },
//     { title: "캐슈넛", description: "고소한 캐슈넛 200g", price: 6000, star: "4.9", review: 450, discount: 15, tag: "SALE", categories: "간식과일견과" },
//     { title: "말린 망고", description: "달콤한 말린 망고 150g", price: 4200, star: "4.6", review: 320, discount: 8, tag: "NEW", categories: "간식과일견과" },
//     { title: "사과칩", description: "바삭한 사과칩 100g", price: 3500, star: "4.8", review: 680, discount: 12, tag: "BEST", categories: "간식과일견과" },
//     { title: "강황 가루", description: "건강에 좋은 강황 가루 150g", price: 4000, star: "4.9", review: 532, discount: 10, tag: "SALE", categories: "양념가루" },
//     { title: "마늘 가루", description: "풍미를 더하는 마늘 가루 100g", price: 2500, star: "4.7", review: 850, discount: 5, tag: "NEW", categories: "양념가루" },
//     { title: "고춧가루", description: "매운 맛을 더하는 고춧가루 200g", price: 3000, star: "4.8", review: 740, discount: 10, tag: "BEST", categories: "양념가루" },
//     { title: "식물성 소시지", description: "100% 식물성으로 만든 소시지 6개입", price: 7200, star: "4.9", review: 430, discount: 12, tag: "SALE", categories: "고기대용" },
//     { title: "콩고기", description: "고기 대체용 콩고기 500g", price: 6500, star: "4.8", review: 312, discount: 10, tag: "NEW", categories: "고기대용" },
//     { title: "채소 고기", description: "양파와 버섯으로 만든 채소 고기 300g", price: 5400, star: "4.7", review: 210, discount: 15, tag: "BEST", categories: "고기대용" },
//     { title: "양배추 볶음", description: "양배추와 버섯을 볶아 만든 간편 요리 300g", price: 2900, star: "4.6", review: 390, discount: 10, tag: "SALE", categories: "채식반찬" },
//     { title: "콩나물 무침", description: "신선한 콩나물과 고추장을 넣어 만든 콩나물 무침", price: 2200, star: "4.8", review: 612, discount: 5, tag: "NEW", categories: "채식반찬" },
//     { title: "된장찌개", description: "전통적인 된장찌개 500g", price: 4200, star: "4.9", review: 340, discount: 12, tag: "NEW", categories: "채식반찬" },
//     { title: "비빔국수", description: "매콤한 양념과 함께 비빈 국수 1인분", price: 4500, star: "4.7", review: 432, discount: 8, tag: "SALE", categories: "채식반찬" },
//     { title: "나물 반찬", description: "시금치, 고사리 등 다양한 나물 반찬 200g", price: 3500, star: "4.8", review: 345, discount: 10, tag: "BEST", categories: "채식반찬" },
//     { title: "에그롤", description: "계란과 채소로 만든 에그롤 5개입", price: 5600, star: "4.7", review: 510, discount: 15, tag: "NEW", categories: "채식반찬" },
//     { title: "호박전", description: "고소한 호박전을 4개입", price: 4000, star: "4.9", review: 720, discount: 12, tag: "SALE", categories: "채식반찬" },
//     { title: "스파게티", description: "토마토 소스와 함께한 클래식 스파게티", price: 7200, star: "4.8", review: 890, discount: 5, tag: "BEST", categories: "간편식" },
//     { title: "카레", description: "맛있는 카레와 밥이 함께 들어있는 간편식", price: 6500, star: "4.9", review: 760, discount: 10, tag: "NEW", categories: "간편식" },
//     { title: "즉석 떡볶이", description: "매운 떡볶이 소스와 떡이 함께 들어있는 간편식", price: 3500, star: "4.7", review: 634, discount: 5, tag: "SALE", categories: "간편식" },
//     { title: "식물성 떡갈비", description: "식물성 떡갈비 4개입", price: 6700, star: "4.8", review: 512, discount: 12, tag: "NEW", categories: "간편식" },
//     { title: "유기농 두부", description: "자연에서 온 유기농 두부 500g", price: 3500, star: "4.9", review: 640, discount: 10, tag: "BEST", categories: "고기대용" },
//     { title: "시금치 스프", description: "신선한 시금치로 만든 건강한 스프 350g", price: 4000, star: "4.8", review: 570, discount: 15, tag: "NEW", categories: "채식반찬" },
//     { title: "미트볼", description: "고기 대체용 식물성 미트볼 10개입", price: 6200, star: "4.7", review: 340, discount: 8, tag: "SALE", categories: "고기대용" },
//     { title: "파프리카 볶음", description: "파프리카와 양파를 볶아 만든 간편 요리 300g", price: 2900, star: "4.6", review: 455, discount: 12, tag: "BEST", categories: "채식반찬" },
//     { title: "치즈 토스트", description: "치즈와 식물성 재료로 만든 치즈 토스트", price: 4500, star: "4.9", review: 480, discount: 10, tag: "SALE", categories: "간편식" },
//     { title: "비건 아이스크림", description: "식물성 재료로 만든 비건 아이스크림 5개입", price: 7200, star: "4.8", review: 410, discount: 5, tag: "NEW", categories: "간식과일견과" },
//     { title: "검정콩 차", description: "검정콩으로 만든 건강한 차 200g", price: 3200, star: "4.7", review: 310, discount: 12, tag: "BEST", categories: "음료" },
//     { title: "고구마 차", description: "달콤한 고구마 맛이 나는 차 200g", price: 2900, star: "4.8", review: 540, discount: 8, tag: "SALE", categories: "음료" },
//     { title: "콩두부", description: "콩으로 만든 식물성 두부 500g", price: 4000, star: "4.9", review: 520, discount: 10, tag: "NEW", categories: "고기대용" },
//     { title: "채소튀김", description: "새콤달콤 채소튀김 6개입", price: 5200, star: "4.6", review: 610, discount: 15, tag: "BEST", categories: "채식반찬" },
//     { title: "쌀국수 스프", description: "향긋한 쌀국수와 채소가 들어간 스프 350g", price: 3500, star: "4.7", review: 450, discount: 12, tag: "NEW", categories: "간편식" },
//     { title: "채소 샐러드", description: "신선한 채소와 드레싱이 들어있는 샐러드 200g", price: 4000, star: "4.8", review: 340, discount: 8, tag: "SALE", categories: "채식반찬" },
//     { title: "오트밀", description: "건강한 오트밀 500g", price: 3600, star: "4.9", review: 390, discount: 10, tag: "BEST", categories: "간편식" },
//     { title: "애호박 볶음", description: "애호박과 마늘을 볶아 만든 간단한 반찬 300g", price: 3200, star: "4.7", review: 410, discount: 15, tag: "NEW", categories: "채식반찬" },
//     { title: "피망 볶음", description: "피망과 양파를 볶아 만든 채식 반찬 200g", price: 2800, star: "4.6", review: 350, discount: 8, tag: "SALE", categories: "채식반찬" },
//     { title: "통밀 파스타", description: "건강한 통밀로 만든 파스타 400g", price: 4900, star: "4.9", review: 530, discount: 5, tag: "NEW", categories: "간편식" },
//     { title: "두부 강정", description: "매콤한 두부 강정 300g", price: 5200, star: "4.8", review: 460, discount: 10, tag: "BEST", categories: "고기대용" },
//     { title: "두부 스테이크", description: "식물성 두부로 만든 고기 대체 스테이크 4개입", price: 6700, star: "4.7", review: 300, discount: 8, tag: "SALE", categories: "고기대용" },
//     { title: "자두잼", description: "자두로 만든 달콤한 잼 200g", price: 3500, star: "4.6", review: 420, discount: 10, tag: "NEW", categories: "간식과일견과" },
//     { title: "고구마 칩", description: "고소하고 바삭한 고구마 칩 150g", price: 2800, star: "4.8", review: 510, discount: 12, tag: "SALE", categories: "간식과일견과" },
//     { title: "후추 믹스", description: "블랙&화이트 후추 믹스 200g", price: 4200, star: "4.8", review: 310, discount: 8, tag: "BEST", categories: "양념가루" },
//     { title: "파프리카 가루", description: "고운 파프리카 향신료 120g", price: 3400, star: "4.7", review: 290, discount: 7, tag: "HOT", categories: "양념가루" },
//     { title: "커민 파우더", description: "커리 요리에 적합한 커민 가루 100g", price: 2500, star: "4.5", review: 210, discount: 6, tag: "NEW", categories: "양념가루" },
//     { title: "양념 갈비소스", description: "풍미 있는 양념 갈비소스 300g", price: 4900, star: "4.8", review: 430, discount: 12, tag: "BEST", categories: "양념가루" },
//     { title: "허브 솔트", description: "허브와 소금을 섞은 다목적 시즈닝 150g", price: 3600, star: "4.7", review: 330, discount: 9, tag: "NEW", categories: "양념가루" },
//     { title: "바질 파우더", description: "파스타와 피자에 적합한 바질 가루 100g", price: 3100, star: "4.6", review: 250, discount: 8, tag: "BEST", categories: "양념가루" },
//     { title: "칠리 파우더", description: "매운 맛을 더하는 칠리 가루 150g", price: 2700, star: "4.5", review: 190, discount: 5, tag: "NEW", categories: "양념가루" },
//     { title: "소고기 육수 가루", description: "진한 소고기 육수 가루 200g", price: 5500, star: "4.9", review: 470, discount: 15, tag: "BEST", categories: "양념가루" },
//     { title: "생강 파우더", description: "고기 요리에 풍미를 더하는 생강 가루 100g", price: 2800, star: "4.5", review: 220, discount: 6, tag: "NEW", categories: "양념가루" },
//     { title: "카레 가루", description: "부드럽고 깊은 맛의 카레 가루 180g", price: 3700, star: "4.8", review: 310, discount: 10, tag: "HOT", categories: "양념가루" },
//     { title: "참깨 가루", description: "고소한 참깨 맛의 건강 가루 200g", price: 4300, star: "4.9", review: 350, discount: 8, tag: "BEST", categories: "양념가루" },
//     { title: "고춧가루 (매운맛)", description: "청양고추로 만든 매운 고춧가루 250g", price: 5200, star: "4.9", review: 450, discount: 10, tag: "BEST", categories: "양념가루" },
//     { title: "양파 가루", description: "요리에 적합한 양파 풍미 가루 150g", price: 3200, star: "4.6", review: 260, discount: 8, tag: "NEW", categories: "양념가루" },
//     { title: "김치 양념 가루", description: "전통 김치 맛을 내는 양념 가루 200g", price: 4800, star: "4.7", review: 390, discount: 10, tag: "BEST", categories: "양념가루" },
//     { title: "화이트 후추 가루", description: "부드러운 풍미의 화이트 후추 120g", price: 3400, star: "4.5", review: 230, discount: 7, tag: "NEW", categories: "양념가루" },
//     { title: "핫 소스 가루", description: "매콤한 맛을 내는 핫 소스 가루 150g", price: 3100, star: "4.4", review: 190, discount: 5, tag: "BEST", categories: "양념가루" },
//     { title: "올리브 가루", description: "신선한 올리브 풍미의 가루 100g", price: 2900, star: "4.7", review: 270, discount: 6, tag: "NEW", categories: "양념가루" },
//     { title: "머스타드 파우더", description: "강한 풍미의 머스타드 가루 150g", price: 3300, star: "4.6", review: 200, discount: 7, tag: "NEW", categories: "양념가루" },
//     { title: "스테이크 시즈닝", description: "스테이크에 적합한 고급 시즈닝 200g", price: 5600, star: "4.9", review: 520, discount: 15, tag: "BEST", categories: "양념가루" },
//     { title: "찹쌀 2kg", description: "쫀득한 찹쌀 2kg", price: 7500, star: "4.8", review: 400, discount: 12, tag: "HOT", categories: "쌀잡곡계란" },
//     { title: "흑미 1kg", description: "영양 가득한 흑미 1kg", price: 6200, star: "4.6", review: 270, discount: 8, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "보리쌀 1.5kg", description: "담백한 맛의 보리쌀 1.5kg", price: 5600, star: "4.5", review: 210, discount: 9, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "유기농 백미 2kg", description: "유기농 인증을 받은 백미 2kg", price: 8400, star: "4.9", review: 510, discount: 15, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "적두 1kg", description: "건강한 식단을 위한 적두 1kg", price: 6700, star: "4.7", review: 340, discount: 10, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "귀리 1kg", description: "풍부한 섬유질을 자랑하는 귀리 1kg", price: 5200, star: "4.6", review: 290, discount: 7, tag: "HOT", categories: "쌀잡곡계란" },
//     { title: "유기농 계란 12구", description: "신선한 유기농 계란 12개", price: 5300, star: "4.8", review: 400, discount: 12, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "찹쌀현미 1kg", description: "쫀득한 찹쌀과 고소한 현미의 조화 1kg", price: 7200, star: "4.7", review: 370, discount: 10, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "녹두 1kg", description: "깨끗하게 선별된 녹두 1kg", price: 5800, star: "4.7", review: 300, discount: 9, tag: "HOT", categories: "쌀잡곡계란" },
//     { title: "강황미 1kg", description: "건강한 강황으로 코팅된 쌀 1kg", price: 8900, star: "4.9", review: 480, discount: 15, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "통밀쌀 1kg", description: "영양이 가득한 통밀쌀 1kg", price: 5700, star: "4.6", review: 240, discount: 8, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "현미찹쌀 혼합 1kg", description: "다양한 영양소를 담은 혼합 곡물 1kg", price: 7600, star: "4.8", review: 450, discount: 11, tag: "HOT", categories: "쌀잡곡계란" },
//     { title: "발아현미 1kg", description: "발아 현미로 더욱 부드럽고 건강하게", price: 6800, star: "4.7", review: 350, discount: 9, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "칼슘 강화 계란 10구", description: "칼슘을 더한 신선한 계란 10개", price: 4600, star: "4.8", review: 300, discount: 10, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "혼합 잡곡 1kg", description: "다양한 잡곡으로 풍미를 더한 혼합 곡물", price: 7400, star: "4.7", review: 340, discount: 10, tag: "HOT", categories: "쌀잡곡계란" },
//     { title: "유기농 찹쌀 1kg", description: "부드러운 맛과 쫀득한 식감의 유기농 찹쌀", price: 8100, star: "4.9", review: 450, discount: 13, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "검은콩 1kg", description: "깨끗하고 영양이 풍부한 검은콩 1kg", price: 6900, star: "4.7", review: 320, discount: 9, tag: "HOT", categories: "쌀잡곡계란" },
//     { title: "레드 퀴노아 500g", description: "영양이 가득한 레드 퀴노아 500g", price: 7900, star: "4.8", review: 380, discount: 11, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "자연 방사 유정란 20구", description: "자연 방사 환경에서 키운 닭의 신선한 유정란 20개", price: 8800, star: "4.9", review: 550, discount: 15, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "찹쌀 2kg", description: "쫀득한 찹쌀 2kg", price: 7500, star: "4.8", review: 400, discount: 12, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "흑미 1kg", description: "영양 가득한 흑미 1kg", price: 6200, star: "4.6", review: 270, discount: 8, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "보리쌀 1.5kg", description: "담백한 맛의 보리쌀 1.5kg", price: 5600, star: "4.5", review: 210, discount: 9, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "유기농 백미 2kg", description: "유기농 인증을 받은 백미 2kg", price: 8400, star: "4.9", review: 510, discount: 15, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "적두 1kg", description: "건강한 식단을 위한 적두 1kg", price: 6700, star: "4.7", review: 340, discount: 10, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "귀리 1kg", description: "풍부한 섬유질을 자랑하는 귀리 1kg", price: 5200, star: "4.6", review: 290, discount: 7, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "유기농 계란 12구", description: "신선한 유기농 계란 12개", price: 5300, star: "4.8", review: 400, discount: 12, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "찹쌀현미 1kg", description: "쫀득한 찹쌀과 고소한 현미의 조화 1kg", price: 7200, star: "4.7", review: 370, discount: 10, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "녹두 1kg", description: "깨끗하게 선별된 녹두 1kg", price: 5800, star: "4.7", review: 300, discount: 9, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "강황미 1kg", description: "건강한 강황으로 코팅된 쌀 1kg", price: 8900, star: "4.9", review: 480, discount: 15, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "통밀쌀 1kg", description: "영양이 가득한 통밀쌀 1kg", price: 5700, star: "4.6", review: 240, discount: 8, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "현미찹쌀 혼합 1kg", description: "다양한 영양소를 담은 혼합 곡물 1kg", price: 7600, star: "4.8", review: 450, discount: 11, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "발아현미 1kg", description: "발아 현미로 더욱 부드럽고 건강하게", price: 6800, star: "4.7", review: 350, discount: 9, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "칼슘 강화 계란 10구", description: "칼슘을 더한 신선한 계란 10개", price: 4600, star: "4.8", review: 300, discount: 10, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "혼합 잡곡 1kg", description: "다양한 잡곡으로 풍미를 더한 혼합 곡물", price: 7400, star: "4.7", review: 340, discount: 10, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "유기농 찹쌀 1kg", description: "부드러운 맛과 쫀득한 식감의 유기농 찹쌀", price: 8100, star: "4.9", review: 450, discount: 13, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "검은콩 1kg", description: "깨끗하고 영양이 풍부한 검은콩 1kg", price: 6900, star: "4.7", review: 320, discount: 9, tag: "SALE", categories: "쌀잡곡계란" },
//     { title: "레드 퀴노아 500g", description: "영양이 가득한 레드 퀴노아 500g", price: 7900, star: "4.8", review: 380, discount: 11, tag: "BEST", categories: "쌀잡곡계란" },
//     { title: "자연 방사 유정란 20구", description: "자연 방사 환경에서 키운 닭의 신선한 유정란 20개", price: 8800, star: "4.9", review: 550, discount: 15, tag: "NEW", categories: "쌀잡곡계란" },
//     { title: "망고 스무디", description: "달콤한 망고로 만든 상큼한 스무디 350ml", price: 5200, star: "4.9", review: 380, discount: 10, tag: "BEST", categories: "음료" },
//     { title: "오렌지 주스", description: "신선한 오렌지로 착즙한 100% 순수 주스 500ml", price: 4600, star: "4.8", review: 420, discount: 12, tag: "NEW", categories: "음료" },
//     { title: "녹차 라떼", description: "부드럽고 풍미 깊은 녹차 라떼 350ml", price: 4500, star: "4.7", review: 310, discount: 8, tag: "SALE", categories: "음료" },
//     { title: "딸기 스무디", description: "싱싱한 딸기로 만든 달콤한 스무디 300ml", price: 5100, star: "4.9", review: 370, discount: 10, tag: "BEST", categories: "음료" },
//     { title: "콜드브루 커피", description: "풍부한 향을 담은 콜드브루 커피 500ml", price: 5900, star: "4.8", review: 450, discount: 11, tag: "SALE", categories: "음료" },
//     { title: "자몽 에이드", description: "톡 쏘는 자몽의 상큼함을 담은 에이드 400ml", price: 4800, star: "4.7", review: 320, discount: 9, tag: "NEW", categories: "음료" },
//     { title: "허브 티", description: "상쾌하고 건강한 허브 티 300ml", price: 3800, star: "4.6", review: 280, discount: 7, tag: "NEW", categories: "음료" },
//     { title: "카카오 밀크", description: "리치한 초콜릿과 부드러운 우유의 조합 500ml", price: 5500, star: "4.8", review: 360, discount: 12, tag: "SALE", categories: "음료" },
//     { title: "코코넛 워터", description: "순수 코코넛 워터로 몸에 수분 충전 500ml", price: 4900, star: "4.8", review: 310, discount: 9, tag: "BEST", categories: "음료" },
//     { title: "유기농 석류 주스", description: "신선한 석류로 만든 유기농 주스 400ml", price: 6800, star: "4.9", review: 510, discount: 15, tag: "NEW", categories: "음료" },
//     { title: "청포도 에이드", description: "청포도의 깔끔한 단맛을 담은 에이드 450ml", price: 4700, star: "4.7", review: 340, discount: 10, tag: "NEW", categories: "음료" },
//     { title: "아메리카노", description: "향이 깊은 원두로 내린 아메리카노 350ml", price: 3900, star: "4.8", review: 450, discount: 8, tag: "SALE", categories: "음료" },
//     { title: "복숭아 아이스티", description: "달콤하고 향긋한 복숭아 아이스티 400ml", price: 4300, star: "4.7", review: 370, discount: 9, tag: "NEW", categories: "음료" },
//     { title: "레몬차", description: "상큼한 레몬의 맛과 향을 담은 따뜻한 차 300ml", price: 3500, star: "4.6", review: 280, discount: 7, tag: "SALE", categories: "음료" },
//     { title: "밀크티", description: "부드러운 홍차와 우유의 조화 350ml", price: 4500, star: "4.8", review: 320, discount: 10, tag: "BEST", categories: "음료" },
//     { title: "파인애플 주스", description: "달콤한 파인애플로 만든 주스 400ml", price: 5100, star: "4.9", review: 420, discount: 12, tag: "NEW", categories: "음료" },
//     { title: "블랙베리 스무디", description: "풍미 깊은 블랙베리로 만든 스무디 350ml", price: 5300, star: "4.8", review: 350, discount: 11, tag: "NEW", categories: "음료" },
//     { title: "말차 에이드", description: "깔끔한 말차의 맛을 에이드로 즐기기 400ml", price: 4900, star: "4.7", review: 310, discount: 9, tag: "SALE", categories: "음료" },
//     { title: "히비스커스 차", description: "향긋한 히비스커스를 담은 따뜻한 차 300ml", price: 3700, star: "4.6", review: 280, discount: 8, tag: "NEW", categories: "음료" },
//     { title: "탄산수", description: "청량감 가득한 탄산수 500ml", price: 2500, star: "4.5", review: 190, discount: 5, tag: "BEST", categories: "음료" },
//     { title: "유기농 아사이 베리 파우더", description: "아사이 베리를 분말로 만든 슈퍼푸드 100g", price: 15000, star: "4.9", review: 480, discount: 10, tag: "BEST", categories: "건강식품" },
//     { title: "스피루리나 캡슐", description: "천연 스피루리나로 만든 건강 보조제 120정", price: 20000, star: "4.8", review: 390, discount: 15, tag: "NEW", categories: "건강식품" },
//     { title: "차전자피 파우더", description: "식이섬유가 풍부한 차전자피 분말 250g", price: 12000, star: "4.7", review: 320, discount: 8, tag: "HOT", categories: "건강식품" },
//     { title: "콜라겐 젤리", description: "피부 건강을 위한 콜라겐 젤리 스틱 30개입", price: 28000, star: "4.9", review: 570, discount: 12, tag: "BEST", categories: "건강식품" },
//     { title: "프로바이오틱스", description: "장 건강에 좋은 유산균 보충제 60캡슐", price: 25000, star: "4.8", review: 420, discount: 10, tag: "NEW", categories: "건강식품" },
//     { title: "비타민 C 분말", description: "순수 비타민 C로 면역력을 높이는 파우더 200g", price: 18000, star: "4.7", review: 310, discount: 9, tag: "NEW", categories: "건강식품" },
//     { title: "식물성 오메가3", description: "식물성 원료로 만든 오메가3 보충제 60캡슐", price: 22000, star: "4.8", review: 350, discount: 11, tag: "HOT", categories: "건강식품" },
//     { title: "크랜베리 추출물", description: "여성 건강을 위한 크랜베리 보충제 90캡슐", price: 24000, star: "4.9", review: 400, discount: 12, tag: "BEST", categories: "건강식품" },
//     { title: "아연 + 마그네슘", description: "체내 균형을 위한 아연과 마그네슘 보충제 90정", price: 17000, star: "4.6", review: 290, discount: 7, tag: "NEW", categories: "건강식품" },
//     { title: "홍삼 농축액", description: "활력을 높이는 프리미엄 홍삼 농축액 120ml", price: 40000, star: "4.9", review: 580, discount: 15, tag: "HOT", categories: "건강식품" },
//     { title: "밀크 시슬 캡슐", description: "간 건강에 좋은 밀크 시슬 보충제 90캡슐", price: 23000, star: "4.7", review: 330, discount: 9, tag: "BEST", categories: "건강식품" },
//     { title: "루테인 플러스", description: "눈 건강을 위한 루테인 보충제 60정", price: 27000, star: "4.8", review: 400, discount: 10, tag: "HOT", categories: "건강식품" },
//     { title: "아사이베리 캡슐", description: "항산화 효과를 위한 아사이베리 추출 캡슐 60정", price: 21000, star: "4.7", review: 310, discount: 8, tag: "NEW", categories: "건강식품" },
//     { title: "유기농 마카 파우더", description: "자연에서 온 에너지 부스터 마카 파우더 150g", price: 19000, star: "4.8", review: 350, discount: 11, tag: "BEST", categories: "건강식품" },
//     { title: "체리 추출물", description: "숙면을 도와주는 체리 추출 보충제 90캡슐", price: 22000, star: "4.9", review: 390, discount: 12, tag: "NEW", categories: "건강식품" },
//     { title: "감초차", description: "몸을 따뜻하게 해주는 감초차 30티백", price: 12000, star: "4.6", review: 250, discount: 8, tag: "HOT", categories: "건강식품" },
//     { title: "홍국 쌀 추출물", description: "콜레스테롤 개선에 도움을 주는 홍국 추출물 60캡슐", price: 20000, star: "4.8", review: 340, discount: 10, tag: "NEW", categories: "건강식품" },
//     { title: "마누카 꿀", description: "항균 작용이 뛰어난 마누카 꿀 250g", price: 35000, star: "4.9", review: 500, discount: 15, tag: "BEST", categories: "건강식품" },
//     { title: "유기농 퀴노아", description: "영양이 풍부한 유기농 퀴노아 1kg", price: 18000, star: "4.7", review: 300, discount: 8, tag: "NEW", categories: "건강식품" },
//     { title: "고구마 가루", description: "건강 간식으로 좋은 고구마 가루 300g", price: 15000, star: "4.8", review: 280, discount: 10, tag: "HOT", categories: "건강식품" }
// );


// const addFollowing = async () => {
//     try {
//         // email이 cyaein@gmail.com인 유저를 찾음
//         const user = await User.findOne({ email: '@gmail.com' });

//         if (!user) {
//             console.log("유저를 찾을 수 없습니다.");
//             return;
//         }

//         // following 배열에 새로운 유저 ID 추가
//         const userIdToFollow = '67935b8d3f9b07e01ab2392b';
//         if (!user.following.includes(userIdToFollow)) {
//             user.following.push(userIdToFollow);
//             await user.save(); // 변경 사항 저장
//             console.log('성공적으로 팔로잉을 추가했습니다.');
//         } else {
//             console.log('이미 해당 유저를 팔로우하고 있습니다.');
//         }
//     } catch (error) {
//         console.error('에러 발생:', error);
//     }
// };

// const addFollower = async () => {
//     try {
//         // email이 cyaein@gmail.com인 유저를 찾음
//         const user = await User.findOne({ email: 'cyaein@gmail.com' });

//         if (!user) {
//             console.log("유저를 찾을 수 없습니다.");
//             return;
//         }

//         // following 배열에 새로운 유저 ID 추가
//         const userIdToFollow = '67935b8d3f9b07e01ab2392b';
//         if (!user.followers.includes(userIdToFollow)) {
//             user.followers.push(userIdToFollow);
//             await user.save(); // 변경 사항 저장
//             console.log('성공적으로 팔로워를 추가했습니다.');
//         } else {
//             console.log('이미 해당 유저를 팔로우하고 있습니다.');
//         }
//     } catch (error) {
//         console.error('에러 발생:', error);
//     }
// };

// addFollower();


import Scrap from "../models/scrap_schema.js"; // Scrap 모델
const addScrap = async () => {
    try {
        const user = await User.findOne({ email: 'cyaein@gmail.com' });

        if (!user) {
            console.log("유저를 찾을 수 없습니다.");
            return;
        }

        // following 배열에 새로운 유저 ID 추가
        const userId = user._id;
        const postId = '67808a3e62d76b07f963a440';
        
        // 스크랩 여부 확인
        const existingScrap = await Scrap.findOne({ userId, postId });

        if (existingScrap) {
            console.log("⚠️ 이미 스크랩한 게시물입니다.");
            return
        }

        // 새로운 스크랩 추가
        const newScrap = new Scrap({ userId, postId });
        await newScrap.save();


    } catch (error) {
        console.error('에러 발생:', error);
    }
};

addScrap();
