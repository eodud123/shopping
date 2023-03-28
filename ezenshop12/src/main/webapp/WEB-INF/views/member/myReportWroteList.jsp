<%@ page language="java" contentType="text/html; charset=EUC-KR"
    pageEncoding="EUC-KR"%>
   <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<!DOCTYPE html>
<html>
<head>
	 
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <!-- Animate.css -->
	<link rel="stylesheet" href="/controller/resources/css/animate.css">
	<!-- Icomoon Icon Fonts-->
	<link rel="stylesheet" href="/controller/resources/css/icomoon.css">

	<!-- Owl Carousel -->
	<link rel="stylesheet" href="/controller/resources/css/owl.carousel.min.css">
	<link rel="stylesheet" href="/controller/resources/css/owl.theme.default.min.css">
	<!-- Theme style  -->
	<link rel="stylesheet" href="/controller/resources/css/style.css">
	<!-- Modernizr JS -->
	<script src="/controller/resources/js/modernizr-2.6.2.min.js"></script>	
<title>�� �ۼ����� ��ȸ</title>
</head>
    
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
	<div class="container">
			<header>
				<h1>�� �ۼ����� ��ȸ</h1>
			</header>
			<hr />
			<section id="container">
			<c:if test="${msg != 'login_error'}">
				<form role="form" method="get">
				<button type="button" class="btn btn-danger" onclick="location.href='${pageContext.request.contextPath}/member/myWroteList'">�����Խ���</button> 
				 <button type="button" class="btn btn-danger" onclick="location.href='${pageContext.request.contextPath}/member/myReportWroteList'">�Ű�Խ���</button>
				 <button type="button" class="btn btn-danger" onclick="location.href='${pageContext.request.contextPath}/member/myQnaWroteList'">���ǰԽ���</button>  
					<br/><br/>
					<h3>�Ű�Խ���</h3>
					<table class="table table-hover">
						<thead>
							<tr><th>��ȣ</th><th>�з�</th><th>����</th><th>�����</th><th>�ۼ���</th></tr>
								</thead>
							<c:forEach items="${reportList}" var = "reportList">
							<c:if test="${member.MEMBER_ID == reportList.member_id}">
							<tr>
								<td><c:out value="${reportList.report_no}" /></td>
								<td><c:out value="${reportList.boardcate}" /></td>
								<td><a href="/controller/member/myReportView?report_no=${reportList.report_no}">${reportList.report_title}</a></td>
								<td><c:out value="${reportList.report_title}" /></td>
								<td><fmt:formatDate value="${reportList.report_regdate}" pattern="yyyy-MM-dd"/></td>
								<td><c:out value="${reportList.member_id}" /></td>
							</tr>
							</c:if>	
						</c:forEach>
					
					</table>
					<div class="col-md-offset-3">
						 <ul class="pagination justify-content-center">
						  <c:if test="${pageMaker2.prev}">
						   <li><a href="myReportWroteList?page=${pageMaker2.startPage - 1}" class="page-link">����</a></li>
						  </c:if> 
						  
						  <c:forEach begin="${pageMaker2.startPage}" end="${pageMaker2.endPage}" var="idx">
						   <li><a href="myReportWroteList?page=${idx}" class="page-link">${idx}</a></li>
						  </c:forEach>
						    
						  <c:if test="${pageMaker2.next && pageMaker2.endPage > 0}">
						   <li><a href="myReportWroteList?page=${pageMaker2.endPage + 1}" class="page-link">����</a></li>
						  </c:if> 
						 </ul>
					</div>
					
					</form>
					</c:if>
				</section>	
				</div>
					<!-- jQuery -->
	<script src="/controller/resources/js/jquery.min.js"></script>
	<!-- jQuery Easing -->
	<script src="/controller/resources/js/jquery.easing.1.3.js"></script>
	<!-- Bootstrap -->
	<script src="/controller/resources/js/bootstrap.min.js"></script>
	<!-- Carousel -->
	<script src="/controller/resources/js/owl.carousel.min.js"></script>
	<!-- Stellar -->
	<script src="/controller/resources/js/jquery.stellar.min.js"></script>
	<!-- Waypoints -->
	<script src="/controller/resources/js/jquery.waypoints.min.js"></script>
	<!-- Counters -->
	<script src="/controller/resources/js/jquery.countTo.js"></script>
	<!-- MAIN JS -->
	<script src="/controller/resources/js/main.js"></script>
				<jsp:include page="../common/footer.jsp"></jsp:include>
				</body>
		</html>