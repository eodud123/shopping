package com.ezen.Dao;

import java.util.List;

import com.ezen.Other.Criteria;
import com.ezen.Vo.ASVO;

public interface ASDAO
{
	//����
	public void see() throws Exception;
	// �ۼ�
	public void write(ASVO vo) throws Exception;
	// ��ȸ
	public ASVO read(int as_no) throws Exception;
	// ����
	public void update(ASVO vo) throws Exception;
	// ����
	public void delete(int as_no) throws Exception;
	//���
	public List<ASVO> list(Criteria cri) throws Exception;
	//�Խù� �� ����
	public int listCount() throws Exception;
}
