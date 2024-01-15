use reqwest::{self, Error};
use reqwest::header::{AUTHORIZATION};
use tokio::runtime::{Handle, Runtime};
use tokio::task;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use serde::de::value;
use tokio::time::timeout;
use std::any::Any;
use std::thread;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{Instant};
use futures::executor::block_on;
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use rand::prelude::*;




pub struct ClientClass {
    prices: Vec<f64>,
    avg_price: f64,
}

impl ClientClass {
    pub async fn valupdate(&mut self) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();
        
        let response: Root= client
            .get("https://api.coincap.io/v2/rates/bitcoin")
            .header(AUTHORIZATION, "7bcda732-11f0-4cfd-b412-78d1a0149a98")
            .send()
            .await?
            .json()
            .await?;
    
             self.prices.push(response.data.rate_usd.parse().unwrap());
       
        
        
    
        Ok(())
    }
    pub fn avgcalculator(&mut self){
        let total: f64 = self.prices.iter().sum();
        self.avg_price = total / self.prices.len() as f64;
    }

    pub async fn client_insantiator( &mut self) {
        let start = Instant::now();
        while start.elapsed().as_secs()<10{
        let _ = self.valupdate().await; 
            
        }
        self.avgcalculator();
   
         
    }
    pub fn generate_key_pair(&mut self) -> (SigningKey, VerifyingKey) {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&private_key);
        (private_key, public_key)
    }
    
    pub fn sign_message(&mut self,private_key: &SigningKey, message: &str) -> Vec<u8> {
        let signature: k256::ecdsa::Signature = private_key.sign(message.as_bytes()); // explicitly specify as_bytes
        let der_signature = signature.to_der();
        der_signature.as_bytes().to_vec()
    }
  
    
}

pub struct AggregatorClass{
     vec_avg_prices: Vec<f64>,
     avg_of_avg_prices: f64,
}

impl  AggregatorClass {
        
        pub fn update_avg(&mut self){
            let t: f64 = self.vec_avg_prices.iter().sum();
            self.avg_of_avg_prices = t / self.vec_avg_prices.len() as f64;
        }
                
         pub fn update_val(&mut self, value: f64){
                self.vec_avg_prices.push(value);

         }
         fn verify_signature(&mut self, public_key: &VerifyingKey, message: &str, signature: &[u8]) -> bool {
            if let Ok(signature) = k256::ecdsa::Signature::from_der(signature) {
                return public_key.verify(message.as_bytes(), &signature).is_ok();
            }
            false
        }
    
}






#[derive(Debug, Serialize, Deserialize)]

pub struct Root{
    data: Data,
    timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Data{
    id: String,
    symbol: String,
    #[serde(rename = "currencySymbol")]
    currency_symbol: String,
    #[serde(rename = "type")]
    type_: String,
    #[serde(rename = "rateUsd")]
    rate_usd: String,

}







#[tokio::main]
async fn main()->Result<(),()> {

    let args: Vec<String> = std::env::args().collect();
    let mode = &args[1];
    let times = &args[2];

    if mode=="cache" && times=="10"{
        multiple_client_intitiator().await;
    }else if mode=="read"{
        let mut path = std::env::current_dir().unwrap().display().to_string();
        path+="/src/output.txt";
         let contents = fs::read_to_string(path)
         .expect("Should have been able to read the file");

        println!("With text:\n{contents}");
    }
    else{
        print!("invalid arguments")
    }
    
       
   
    
    Ok(())
}


async fn multiple_client_intitiator(){
   
    let aggr = Arc::new(Mutex::new(AggregatorClass{vec_avg_prices: Vec::new(), avg_of_avg_prices: 0.0}));
    
    
    let agg = aggr.clone();
    let t1 = tokio::task::spawn(async move  {
        let mut c1 = ClientClass{prices: Vec::new(), avg_price: 0.0};
        c1.client_insantiator().await;
        let (private_key, public_key) = c1.generate_key_pair();
        let message = "Hello, OP_CHECKSIG!";
        let signature = c1.sign_message(&private_key, message);
        let mut temp_agg = agg.lock().unwrap();
        let is_valid = temp_agg.verify_signature(&public_key, message, &signature);
        if is_valid{
            println!("verified!");
            temp_agg.update_val(c1.avg_price);
            let mut path = std::env::current_dir().unwrap().display().to_string();
            path+="/src/output.txt";
            let mut file = OpenOptions::new().append(true).open(path).expect("Cannot open file");
            for ele in c1.prices.iter(){
               let _ = file.write_all(ele.to_string().as_bytes());
            }
            let _ = file.write_all("average of client1 is:".as_bytes());
            let _ = file.write_all(c1.avg_price.to_string().as_bytes());
        }else{
            println!("client verification failed");
        }
        

    

    });
    let agg = aggr.clone();
    let t2 = tokio::task::spawn(async move  {
        let mut c2 = ClientClass{prices: Vec::new(), avg_price: 0.0};
        c2.client_insantiator().await;
        let (private_key, public_key) = c2.generate_key_pair();
        let message = "Hello, OP_CHECKSIG!";
        let signature = c2.sign_message(&private_key, message);
        let mut temp_agg = agg.lock().unwrap();
        let is_valid = temp_agg.verify_signature(&public_key, message, &signature);
        if is_valid{
            println!("verified!");
            temp_agg.update_val(c2.avg_price);
            let mut path = std::env::current_dir().unwrap().display().to_string();
            path+="/src/output.txt";
            let mut file = OpenOptions::new().append(true).open(path).expect("Cannot open file");
            for ele in c2.prices.iter(){
                let _ = file.write_all(ele.to_string().as_bytes());
            }
            let _ = file.write_all("average of client1 is:".as_bytes());
            let _ = file.write_all(c2.avg_price.to_string().as_bytes());
        }else{
            println!("client verification failed");
        }

    });
    let agg = aggr.clone();
    let t3 = tokio::task::spawn(async move {
        let mut c3 = ClientClass{prices: Vec::new(), avg_price: 0.0};
        c3.client_insantiator().await;
        let (private_key, public_key) = c3.generate_key_pair();
        let message = "Hello, OP_CHECKSIG!";
        let signature = c3.sign_message(&private_key, message);
        let mut temp_agg = agg.lock().unwrap();
        let is_valid = temp_agg.verify_signature(&public_key, message, &signature);
        if is_valid{
            println!("verified!");
            temp_agg.update_val(c3.avg_price);
            let mut path = std::env::current_dir().unwrap().display().to_string();
            path+="/src/output.txt";
            let mut file = OpenOptions::new().append(true).open(path).expect("Cannot open file");
            for ele in c3.prices.iter(){
                let _ =file.write_all(ele.to_string().as_bytes());
            }
            let _ = file.write_all("average of client1 is:".as_bytes());
            let _ = file.write_all(c3.avg_price.to_string().as_bytes());
        }else{
            println!("client verification failed");
        }
    });
    let agg = aggr.clone();
    let t4 = tokio::task::spawn(async move {
        let mut c4 = ClientClass{prices: Vec::new(), avg_price: 0.0};
        c4.client_insantiator().await;
        let (private_key, public_key) = c4.generate_key_pair();
        let message = "Hello, OP_CHECKSIG!";
        let signature = c4.sign_message(&private_key, message);
        let mut temp_agg = agg.lock().unwrap();
        let is_valid = temp_agg.verify_signature(&public_key, message, &signature);
        if is_valid{
            println!("verified!");
            temp_agg.update_val(c4.avg_price);
            let mut path = std::env::current_dir().unwrap().display().to_string();
            path+="/src/output.txt";
            let mut file = OpenOptions::new().append(true).open(path).expect("Cannot open file");
            for ele in c4.prices.iter(){
                let _ = file.write_all(ele.to_string().as_bytes());
            }
            let _ = file.write_all("average of client1 is:".as_bytes());
            let _ = file.write_all(c4.avg_price.to_string().as_bytes());
        }else{
            println!("client verification failed");
        }
    });
    let agg = aggr.clone();
    let t5 = tokio::task::spawn(async move {
        let mut c5 = ClientClass{prices: Vec::new(), avg_price: 0.0};
        c5.client_insantiator().await;
        let (private_key, public_key) = c5.generate_key_pair();
        let message = "Hello, OP_CHECKSIG!";
        let signature = c5.sign_message(&private_key, message);
        let mut temp_agg = agg.lock().unwrap();
        let is_valid = temp_agg.verify_signature(&public_key, message, &signature);
        if is_valid{
            println!("verified!");
            temp_agg.update_val(c5.avg_price);
            let mut path = std::env::current_dir().unwrap().display().to_string();
            path+="/src/output.txt";
            let mut file = OpenOptions::new().append(true).open(path).expect("Cannot open file");
            for ele in c5.prices.iter(){
                let _ = file.write_all(ele.to_string().as_bytes());
            }
            let _ = file.write_all("average of client1 is:".as_bytes());
            let _ = file.write_all(c5.avg_price.to_string().as_bytes());
        }else{
            println!("client verification failed");
        }
    });
    let _ = tokio::join!(t1,t2,t3,t4,t5);
    aggr.lock().unwrap().update_avg();
    print!("Cache compllete average price of BTC in USD is {}",aggr.lock().unwrap().avg_of_avg_prices);
}

