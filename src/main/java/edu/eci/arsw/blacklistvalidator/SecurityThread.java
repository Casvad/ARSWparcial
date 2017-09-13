/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author 2105534
 */
public class SecurityThread extends Thread{
    int limI;
    int limS;
    String ipaddress;
    
    public SecurityThread(int limI,int limS, String ipaddress){
        //System.out.println("LimI:"+limI+" y LimS: "+limS);
        this.limI=limI;
        this.limS=limS;
        this.ipaddress=ipaddress;
    }
    
    public void run(){
        
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        
        for (int i = limI; i < limS && !HostBlackListsValidator.isYaTermine(); i++) {
          if(skds.isInBlackListServer(i, ipaddress)){
              
              HostBlackListsValidator.agregarElemento(i);//agrega Elemento a lista
          }  
        }
        
        if(HostBlackListsValidator.soyElUltimo()){
            
        }
        
    }
    
}
