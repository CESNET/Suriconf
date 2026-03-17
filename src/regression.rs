
use scirs2_core::ndarray::{Array1, Array2};
use scirs2_stats::{huber_regression, theilslopes};
pub fn  my_huber_regression(vector_values: Vec<f64>, uptime: u64, time_period: u64, num_elements: u64) -> Vec<f64> {
    let loops = uptime/(time_period*num_elements);
    let mut huber_reg_vec: Vec<f64> = Vec::new();
    let vector_time: Vec<f64> = (0..uptime).step_by(time_period as usize).map(|v| v as f64).collect();
    let mut counter = 0;

    for _ in 0..loops {
        let x = Array2::from_shape_vec((num_elements as usize, 1), vector_time[(counter*num_elements) as usize..((counter+1)*num_elements) as usize].to_vec()).expect("Operation failed");
        let y = Array1::from_vec(vector_values[(counter*num_elements) as usize..((counter+1)*num_elements) as usize].to_vec());

         let result = match huber_regression(&x.view(), &y.view(), None, None, None, None, None, None) {
             Ok(result) => {result},
             Err(e) => {
                  //println!("{e} {:?}", y);
                 huber_reg_vec.push(0.0);
                 continue}
         };

        //assert_eq!(result.coefficients.len(), 2);  // Intercept and slope
        huber_reg_vec.push(*result.coefficients.last().expect("Unable to get slope."));
        //assert!(result.r_squared >= 0.0 && result.r_squared <= 1.0);
        counter+=1;
    }
    huber_reg_vec
}

pub fn my_theil_sen_regression(vector_values: Vec<f64>, uptime: u64, time_period: u64, num_elements: u64) -> Vec<f64>{
    let loops = uptime/(time_period*num_elements);
    let mut theil_sen_vec: Vec<f64> = Vec::new();
    let vector_time: Vec<f64> = (0..uptime).step_by(time_period as usize).map(|v| v as f64).collect();
    let mut counter = 0;


     for _ in 0..loops {
         let x = Array1::from_vec(vector_time[(counter*num_elements) as usize..((counter+1)*num_elements) as usize].to_vec());
         let y = Array1::from_vec(vector_values[(counter*num_elements) as usize..((counter+1)*num_elements) as usize].to_vec());

         let result = match theilslopes(&x.view(), &y.view(), None, None){
             Ok(result) => {result},
             Err(e) => {
                 //println!("{e} {:?}", y);
                 theil_sen_vec.push(0.0);
                continue}
         };
         theil_sen_vec.push(result.slope);
         counter+=1;

     }
    theil_sen_vec

    // The Theil-Sen estimator should be less affected by the outlier
    //assert!(result.slope > 0.0f64);  // Slope should be positive
    //assert!(result.intercept > -100.0f64);
}
