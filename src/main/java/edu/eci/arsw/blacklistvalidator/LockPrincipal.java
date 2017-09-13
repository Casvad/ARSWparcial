/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

/**
 *
 * @author 2105534
 */
public class LockPrincipal {
    static LockPrincipal o= new LockPrincipal();
    
    private LockPrincipal(){
        
    }
    
    public static LockPrincipal getLock(){
        return o;
    }
}
