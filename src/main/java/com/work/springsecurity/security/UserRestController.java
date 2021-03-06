package com.work.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import props.ActorPro;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@RestController
@RequestMapping(value="/user")
public class UserRestController {

  @Autowired
  DriverManagerDataSource dataSource;
  @RequestMapping(value = "allUser", method = RequestMethod.GET)
  public HashMap<String, Object> allActor(){
    HashMap<String, Object> hm = new HashMap<>();
    List<ActorPro> ls = new ArrayList<>();
    try {
      String query = "Select * from actor";
      PreparedStatement pre = dataSource.getConnection().prepareStatement(query);
      ResultSet rs = pre.executeQuery();
      while(rs.next()){
        ActorPro ac = new ActorPro();
        ac.setActor_id(rs.getInt("actor_id"));
        ac.setFirst_name(rs.getString("first_name"));
        ls.add(ac);
      }
      hm.put("userList",ls);
    } catch (Exception e) {
      System.err.println("WARNN : " + e);
    }
    // hm.put("name", "Ali Bilmem");
    return hm;
  }
}
