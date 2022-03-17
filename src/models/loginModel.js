const mongoose = require('mongoose');
const validator =  require('validator');
const bcryptjs = require('bcryptjs');

const LoginSchema = new mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true }
});

const LoginModel = mongoose.model('Login', LoginSchema);

class Login {
  constructor(body){
    this.body = body;
    this.errors = [];
    this.user = null;
  }

  async register(){
    this.valida();

    if(this.errors.length > 0) return;

    await this.userExists();

    if(this.errors.length > 0) return;

    //criptografando a senha
    const salt = bcryptjs.genSaltSync();
    this.body.password = bcryptjs.hashSync(this.body.password, salt);
    try{
      
      this.user = await LoginModel.create(this.body);
    }catch(e){
      console.log(e);
    }
    
  }


  async userExists(){
    const user = await LoginModel.findOne({email: this.body.email});
  
    if(user) this.errors.push('usuario já cadastrado');
  }

  valida(){
    this.cleanUp();
    //validação
    //o email precisa ser válido
    if(!validator.isEmail(this.body.email)){
      this.errors.push('Email invalido');
    }

    // a senha precisa ter entre 3 e 50
    if(this.body.password.lenght < 3 || this.body.password.lenght > 50){
      this.errors.push('A senha precisa ter entre 3 e 50 caracteres.');
    }
  }

  cleanUp(){
    for(const key in this.body){
      if(typeof this.body[key] !== 'string'){
        this.body[key] = '';
      }
    }

    this.body = {
      email: this.body.email,
      password: this.body.password
    };
  }
}

module.exports = Login;
