package com.ezen.Dao;

import java.util.List;

import javax.inject.Inject;
import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.Criteria;
import com.ezen.Vo.ASVO;

@Repository
public class ASDAOImpl implements ASDAO
{
	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.asMapper";
	
	//����
	@Override
	public void see() throws Exception{
		sql.insert(namespace +".as");
	}
	//�ۼ�
	@Override
	public void write(ASVO vo) throws Exception{
		sql.insert(namespace + ".asInsert", vo);
	}
	//��ȸ
	@Override
	public ASVO read(int as_no) throws Exception{
		return sql.selectOne(namespace + ".asSelect", as_no);
	}
	 // ����
	 @Override
	 public void update(ASVO vo) throws Exception {
	  sql.update(namespace + ".asUpdate", vo);
	 }

	 // ����
	 @Override
	 public void delete(int as_no) throws Exception {
	  sql.delete(namespace + ".asDelete", as_no);
	 }
	 
	 //���
	 @Override
	 public List<ASVO> list(Criteria cri) throws Exception{
		 return sql.selectList(namespace + ".asList", cri);
	 }
	 
	 //���ù� �� ����
	 public int listCount() throws Exception{
		 return sql.selectOne(namespace + ".listCount");
	 }
}
